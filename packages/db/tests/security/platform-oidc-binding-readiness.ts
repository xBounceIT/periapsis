import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import postgres from "postgres";

type ReadinessRow = {
  catalog_digest: string;
  private_ready: boolean;
  public_ready: boolean;
};

const configuredDatabaseUrl =
  process.env.PERIAPSIS_PLATFORM_OIDC_BINDING_READINESS_TEST_DATABASE_URL;
if (
  configuredDatabaseUrl === undefined ||
  configuredDatabaseUrl.trim() === ""
) {
  throw new Error(
    "PERIAPSIS_PLATFORM_OIDC_BINDING_READINESS_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const admin = postgres(configuredDatabaseUrl, {
  max: 1,
  onnotice: () => undefined,
});

const runtimeLogins = [
  ["periapsis_api_login", "periapsis_api", 40],
  ["periapsis_worker_login", "periapsis_worker", 20],
  ["periapsis_notifier_login", "periapsis_notifier", 20],
  ["periapsis_auditor_login", "periapsis_auditor", -1],
] as const;

async function readiness(): Promise<ReadinessRow> {
  const [row] = await admin<ReadinessRow[]>`
    SELECT
      app.private_release_runtime_dependency_surface_hash_v58()
        AS catalog_digest,
      app.private_release_runtime_schema_readiness_v58()
        AS private_ready,
      app.release_runtime_schema_readiness_v58()
        AS public_ready
  `;
  assert(row, "readiness query returned no row");
  return row;
}

async function assertReady(expectedHash: string): Promise<void> {
  const row = await readiness();
  assert.equal(row.catalog_digest, expectedHash);
  assert.equal(row.private_ready, true);
  assert.equal(row.public_ready, true);
}

async function assertDigestRejected(expectedHash: string): Promise<void> {
  const row = await readiness();
  assert.notEqual(row.catalog_digest, expectedHash);
  assert.equal(row.private_ready, false);
  assert.equal(row.public_ready, false);
}

async function enableScramLogin(login: string): Promise<void> {
  const password = randomBytes(32).toString("base64url");
  const [command] = await admin<{ statement: string }[]>`
    SELECT format(
      'ALTER ROLE %I LOGIN PASSWORD %L',
      ${login}::text,
      ${password}::text
    ) AS statement
  `;
  assert(command, `could not build SCRAM provisioning command for ${login}`);
  await admin.unsafe(command.statement);
}

async function bestEffort(statement: string): Promise<void> {
  try {
    await admin.unsafe(statement);
  } catch {
    // Preserve the first test failure while making the isolated database reusable.
  }
}

try {
  const existing = await admin<{ rolname: string }[]>`
    SELECT rolname
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'periapsis_api_login',
      'periapsis_worker_login',
      'periapsis_notifier_login',
      'periapsis_auditor_login'
    )
  `;
  assert.equal(
    existing.length,
    0,
    "readiness lifecycle test requires fresh, unprovisioned runtime logins",
  );

  const baseline = await readiness();
  assert.equal(baseline.private_ready, true);
  assert.equal(baseline.public_ready, true);
  const baselineHash = baseline.catalog_digest;

  await Promise.all(
    runtimeLogins.map(([login, , connectionLimit]) =>
      admin.unsafe(
        `CREATE ROLE ${login} NOLOGIN NOSUPERUSER INHERIT NOCREATEDB ` +
          "NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
          `CONNECTION LIMIT ${connectionLimit}`,
      ),
    ),
  );
  await assertDigestRejected(baselineHash);

  await Promise.all(
    runtimeLogins.map(([login, group]) =>
      admin.unsafe(
        `GRANT ${group} TO ${login} ` +
          "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
      ),
    ),
  );
  await assertReady(baselineHash);

  await admin.unsafe("ALTER ROLE periapsis_api_login LOGIN");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_api_login NOLOGIN");
  await assertReady(baselineHash);

  await admin.unsafe("SET password_encryption = 'scram-sha-256'");
  await Promise.all(runtimeLogins.map(([login]) => enableScramLogin(login)));
  await assertReady(baselineHash);

  await admin.unsafe("ALTER ROLE periapsis_notifier_login NOLOGIN");
  await assertReady(baselineHash);
  await admin.unsafe("REVOKE periapsis_notifier FROM periapsis_notifier_login");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_notifier_login LOGIN");
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "GRANT periapsis_notifier TO periapsis_notifier_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );
  await assertReady(baselineHash);

  await admin.unsafe(
    "GRANT periapsis_api TO periapsis_api_login " +
      "WITH ADMIN FALSE, INHERIT FALSE, SET TRUE",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "GRANT periapsis_api TO periapsis_api_login " +
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
  );
  await assertReady(baselineHash);

  await admin.unsafe("ALTER ROLE periapsis_api_login CREATEDB");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_api_login NOCREATEDB");
  await assertReady(baselineHash);

  await admin.unsafe("ALTER ROLE periapsis_api_login CONNECTION LIMIT 0");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_api_login CONNECTION LIMIT 40");
  await assertReady(baselineHash);

  await admin.unsafe(
    "ALTER ROLE periapsis_api_login VALID UNTIL '2099-01-01T00:00:00Z'",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_api_login VALID UNTIL 'infinity'");
  await assertReady(baselineHash);

  await admin.unsafe("GRANT periapsis_auditor TO periapsis_api_login");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("REVOKE periapsis_auditor FROM periapsis_api_login");
  await assertReady(baselineHash);

  await admin.unsafe(
    "ALTER ROLE periapsis_api_login SET statement_timeout = '1s'",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe("ALTER ROLE periapsis_api_login RESET ALL");
  await assertReady(baselineHash);

  await admin.unsafe(
    "GRANT SET ON PARAMETER statement_timeout TO periapsis_api_login",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "REVOKE SET ON PARAMETER statement_timeout FROM periapsis_api_login",
  );
  await assertReady(baselineHash);

  await admin.unsafe(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "GRANT SELECT ON TABLES TO periapsis_worker_login",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "REVOKE SELECT ON TABLES FROM periapsis_worker_login",
  );
  await assertReady(baselineHash);

  await admin.unsafe(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "GRANT ALL PRIVILEGES ON TABLES TO periapsis_api_login",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "REVOKE ALL PRIVILEGES ON TABLES FROM periapsis_api_login",
  );
  await assertReady(baselineHash);

  await admin.unsafe("GRANT SELECT ON public.tenants TO periapsis_api_login");
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "REVOKE SELECT ON public.tenants FROM periapsis_api_login",
  );
  await assertReady(baselineHash);

  await admin.unsafe("GRANT USAGE ON SCHEMA app TO periapsis_api_login");
  await assertDigestRejected(baselineHash);
  await admin.unsafe("REVOKE USAGE ON SCHEMA app FROM periapsis_api_login");
  await assertReady(baselineHash);

  await admin.unsafe(
    "GRANT EXECUTE ON FUNCTION " +
      "app.start_totp_enrollment_v1(jsonb) " +
      "TO periapsis_api_login",
  );
  await assertDigestRejected(baselineHash);
  await admin.unsafe(
    "REVOKE EXECUTE ON FUNCTION " +
      "app.start_totp_enrollment_v1(jsonb) " +
      "FROM periapsis_api_login",
  );
  await assertReady(baselineHash);
} finally {
  await bestEffort(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "REVOKE SELECT ON TABLES FROM periapsis_worker_login",
  );
  await bestEffort(
    "ALTER DEFAULT PRIVILEGES FOR ROLE periapsis_api_login IN SCHEMA public " +
      "REVOKE ALL PRIVILEGES ON TABLES FROM periapsis_api_login",
  );
  await bestEffort(
    "REVOKE SET ON PARAMETER statement_timeout FROM periapsis_api_login",
  );
  await bestEffort("REVOKE SELECT ON public.tenants FROM periapsis_api_login");
  await bestEffort("REVOKE USAGE ON SCHEMA app FROM periapsis_api_login");
  await bestEffort(
    "REVOKE EXECUTE ON FUNCTION " +
      "app.start_totp_enrollment_v1(jsonb) " +
      "FROM periapsis_api_login",
  );
  await bestEffort("ALTER ROLE periapsis_api_login RESET ALL");
  await bestEffort("REVOKE periapsis_auditor FROM periapsis_api_login");
  await Promise.all(
    runtimeLogins.map(([login, group]) =>
      bestEffort(`REVOKE ${group} FROM ${login}`),
    ),
  );
  await Promise.all(
    runtimeLogins.map(([login]) => bestEffort(`DROP ROLE ${login}`)),
  );
  await admin.end();
}
