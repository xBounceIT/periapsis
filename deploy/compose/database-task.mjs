import { spawn } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, resolve } from "node:path";

import {
  parseDeploymentEnvironment,
  validateAdministratorDatabaseUrl,
} from "./database-task-config.mjs";

const databasePackage = resolve("packages/db/package.json");
const requireFromDatabasePackage = createRequire(databasePackage);
const postgres = requireFromDatabasePackage("postgres");
const mode = process.argv[2] ?? "migrate";
const taskModes = new Set(["migrate", "provision-notifier", "seed"]);
const databaseCodes = new Set([
  "DATABASE_TASK_FAILED",
  "UNSUPPORTED_TASK",
  "INVALID_SECRET",
  "INVALID_DATABASE_URL_FILE",
  "DATABASE_URL_FILE_REQUIRED",
  "INVALID_ENVIRONMENT",
  "INVALID_DATABASE_URL",
  "DATABASE_TLS_REQUIRED",
  "ROLE_STATEMENT_FAILED",
  "INVALID_WEBHOOK_PLAIN_LOCAL_OPT_IN",
  "WEBHOOK_PLAIN_LOCAL_PRODUCTION_FORBIDDEN",
  "MIGRATION_DATABASE_VERSION_UNSUPPORTED",
  "MIGRATION_DATABASE_ADMIN_UNSUPPORTED",
  "MIGRATION_DATABASE_LOCALE_UNSUPPORTED",
  "MIGRATION_CLIENT_INCOMPATIBLE",
  "MIGRATION_BUNDLE_DIVERGED",
  "MIGRATION_JOURNAL_DIVERGED",
  "MIGRATION_JOURNAL_UNAVAILABLE",
  "MIGRATION_SEALER_DIVERGED",
  "MIGRATION_LOCK_UNAVAILABLE",
  "MIGRATION_LOCK_LOST",
  "ENOENT",
  "EACCES",
  "EPERM",
  "EROFS",
  "ECONNREFUSED",
  "ENOTFOUND",
  "ETIMEDOUT",
  "08001",
  "08006",
  "28P01",
  "42501",
  "42702",
  "42P18",
  "42P01",
  "57014",
  "55P03",
  "23505",
  "3D000",
  "SIGNAL_SIGTERM",
  "SIGNAL_SIGKILL",
  "SIGNAL_SIGILL",
  "SIGNAL_SIGABRT",
]);
let phase = "configuration";

try {
  const environment = parseDeploymentEnvironment(process.env["PERIAPSIS_ENV"]);
  const webhookPlainLocalOptIn = parseWebhookPlainLocalOptIn(
    environment,
    process.env["PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL"],
  );
  const databaseUrl = await administratorDatabaseUrl(environment);

  if (mode === "migrate") {
    phase = "migration";
    await runDatabaseScript("src/admin/migrate.js", databaseUrl);
    phase = "runtime_credentials";
    const passwords = {
      api: await readSecret("api_database_password"),
      worker: await readSecret("worker_database_password"),
    };
    if (environment === "production") {
      passwords.notifier = await readSecret("notifier_database_password");
    }
    phase = "runtime_provision";
    await provisionRuntimeLogins(databaseUrl, passwords, {
      webhookPlainLocalOptIn,
    });
  } else if (mode === "provision-notifier") {
    phase = "runtime_credentials";
    const passwords = {
      notifier: await readSecret("notifier_database_password"),
    };
    phase = "runtime_provision";
    await provisionRuntimeLogins(databaseUrl, passwords, {
      webhookPlainLocalOptIn,
    });
  } else if (mode === "seed") {
    phase = "seed";
    await runDatabaseScript("seeds/seed.js", databaseUrl);
  } else {
    throw Object.assign(new Error("unsupported database task"), {
      code: "UNSUPPORTED_TASK",
    });
  }
} catch (error) {
  process.stderr.write(
    `${JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "error",
      service: "database-task",
      event: "database_task_failed",
      mode: taskModes.has(mode) ? mode : "unsupported",
      phase,
      code: diagnosticCode(error),
    })}\n`,
  );
  process.exitCode = 1;
}

function diagnosticCode(error) {
  try {
    const candidate =
      typeof error === "object" && error !== null ? error.code : undefined;
    if (typeof candidate === "string") {
      if (databaseCodes.has(candidate)) return candidate;
      const exit = /^EXIT_([1-9][0-9]{0,2})$/u.exec(candidate);
      if (exit && Number(exit[1]) <= 255) return candidate;
    }
  } catch {
    // A nonstandard code getter must not escape the redacted error boundary.
  }
  return "UNCLASSIFIED";
}

async function readSecret(name) {
  const value = (await readFile(`/run/secrets/${name}`, "utf8")).trim();
  if (value.length < 16) {
    throw Object.assign(new Error("invalid secret"), {
      code: "INVALID_SECRET",
    });
  }
  return value;
}

async function administratorDatabaseUrl(environment) {
  const file = process.env["PERIAPSIS_DATABASE_ADMIN_URL_FILE"];
  if (file !== undefined) {
    if (!isAbsolute(file)) {
      throw Object.assign(new Error("invalid database URL file"), {
        code: "INVALID_DATABASE_URL_FILE",
      });
    }
    const details = await stat(file);
    if (!details.isFile() || details.size < 1 || details.size > 4_096) {
      throw Object.assign(new Error("invalid database URL file"), {
        code: "INVALID_DATABASE_URL_FILE",
      });
    }
    const value = (await readFile(file, "utf8")).trim();
    return validateAdministratorDatabaseUrl(value, {
      production: environment === "production",
    });
  }
  if (environment === "production") {
    throw Object.assign(new Error("database URL file is required"), {
      code: "DATABASE_URL_FILE_REQUIRED",
    });
  }

  const password = await readSecret("postgres_password");
  const host = process.env["PERIAPSIS_DATABASE_HOST"] ?? "postgres";
  const port = process.env["PERIAPSIS_DATABASE_PORT"] ?? "5432";
  const database = process.env["PERIAPSIS_DATABASE_NAME"] ?? "periapsis";
  const user = process.env["PERIAPSIS_DATABASE_ADMIN_USER"] ?? "postgres";
  const url = new URL(`postgresql://${host}:${port}/${database}`);
  url.username = user;
  url.password = password;
  url.searchParams.set("sslmode", "disable");
  return validateAdministratorDatabaseUrl(url.toString(), {
    production: false,
  });
}

async function runDatabaseScript(relativeScript, databaseUrl) {
  const script = resolve("packages/db", relativeScript);
  await new Promise((resolveProcess, rejectProcess) => {
    const child = spawn(process.execPath, [script], {
      cwd: resolve("packages/db"),
      env: {
        ...process.env,
        DATABASE_URL: databaseUrl,
      },
      stdio: "inherit",
    });
    child.once("error", rejectProcess);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolveProcess();
        return;
      }
      rejectProcess(
        Object.assign(new Error("database script failed"), {
          code: signal === null ? `EXIT_${String(code)}` : `SIGNAL_${signal}`,
        }),
      );
    });
  });
}

async function provisionRuntimeLogins(databaseUrl, passwords, options) {
  const sql = postgres(databaseUrl, {
    connect_timeout: 10,
    max: 1,
    onnotice: () => undefined,
  });

  try {
    await sql.begin(async (transaction) => {
      await transaction.unsafe(`
        DO $provision$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'periapsis_api_login') THEN
            CREATE ROLE "periapsis_api_login";
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'periapsis_worker_login') THEN
            CREATE ROLE "periapsis_worker_login";
          END IF;
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'periapsis_notifier_login') THEN
            CREATE ROLE "periapsis_notifier_login";
          END IF;
        END
        $provision$
      `);
      await transaction.unsafe(
        "SET LOCAL password_encryption = 'scram-sha-256'",
      );

      if (passwords.api !== undefined) {
        await configureLogin(transaction, {
          login: "periapsis_api_login",
          memberOf: "periapsis_api",
          password: passwords.api,
          connectionLimit: 40,
        });
      }
      if (passwords.worker !== undefined) {
        await configureLogin(transaction, {
          login: "periapsis_worker_login",
          memberOf: "periapsis_worker",
          password: passwords.worker,
          connectionLimit: 20,
        });
      }
      if (passwords.notifier !== undefined) {
        await configureLogin(transaction, {
          login: "periapsis_notifier_login",
          memberOf: "periapsis_notifier",
          password: passwords.notifier,
          connectionLimit: 20,
        });
      }
      await provisionWebhookPlainLocalRoleOptIns(
        transaction,
        passwords,
        options.webhookPlainLocalOptIn,
      );
    });
  } finally {
    await sql.end({ timeout: 5 });
  }
}

async function provisionWebhookPlainLocalRoleOptIns(
  transaction,
  passwords,
  enabled,
) {
  const [surface] = await transaction`
    SELECT pg_catalog.to_regclass(
      'public.webhook_plain_local_runtime_role_opt_ins'
    ) IS NOT NULL AS exists
  `;
  if (surface?.exists !== true) return;

  if (passwords.api !== undefined) {
    await upsertWebhookPlainLocalRoleOptIn(
      transaction,
      "periapsis_api_login",
      enabled,
    );
  }
  if (passwords.notifier !== undefined) {
    await upsertWebhookPlainLocalRoleOptIn(
      transaction,
      "periapsis_notifier_login",
      enabled,
    );
  }
}

async function upsertWebhookPlainLocalRoleOptIn(
  transaction,
  roleName,
  enabled,
) {
  await transaction`
    INSERT INTO public.webhook_plain_local_runtime_role_opt_ins AS current_opt_in (
      role_name,
      enabled,
      updated_at
    ) VALUES (
      ${roleName},
      ${enabled},
      pg_catalog.clock_timestamp()
    )
    ON CONFLICT (role_name) DO UPDATE
    SET enabled = EXCLUDED.enabled,
        updated_at = EXCLUDED.updated_at
    WHERE current_opt_in.enabled IS DISTINCT FROM EXCLUDED.enabled
  `;
}

function parseWebhookPlainLocalOptIn(environment, value) {
  const raw = value ?? "false";
  if (raw !== "true" && raw !== "false") {
    throw Object.assign(new Error("invalid webhook plaintext opt-in"), {
      code: "INVALID_WEBHOOK_PLAIN_LOCAL_OPT_IN",
    });
  }
  if (raw === "true" && environment === "production") {
    throw Object.assign(new Error("unsafe webhook plaintext opt-in"), {
      code: "WEBHOOK_PLAIN_LOCAL_PRODUCTION_FORBIDDEN",
    });
  }
  return raw === "true";
}

async function configureLogin(transaction, specification) {
  const [alterRole] = await transaction`
    SELECT format(
      'ALTER ROLE %I WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s VALID UNTIL ''infinity'' PASSWORD %L',
      ${specification.login}::text,
      ${specification.connectionLimit}::integer,
      ${specification.password}::text
    ) AS statement
  `;
  const [grantRole] = await transaction`
    SELECT format(
      'GRANT %I TO %I WITH ADMIN FALSE, INHERIT TRUE, SET TRUE',
      ${specification.memberOf}::text,
      ${specification.login}::text
    ) AS statement
  `;
  if (
    alterRole?.statement === undefined ||
    grantRole?.statement === undefined
  ) {
    throw Object.assign(new Error("role statement generation failed"), {
      code: "ROLE_STATEMENT_FAILED",
    });
  }
  await transaction.unsafe(alterRole.statement);
  const [resetRole] = await transaction`
    SELECT format('ALTER ROLE %I RESET ALL', ${specification.login}::text)
      AS statement
  `;
  if (resetRole?.statement === undefined) {
    throw Object.assign(new Error("role reset statement generation failed"), {
      code: "ROLE_STATEMENT_FAILED",
    });
  }
  await transaction.unsafe(resetRole.statement);
  const staleMemberships = await transaction`
    SELECT format(
      'REVOKE %I FROM %I GRANTED BY %I CASCADE',
      granted_role.rolname,
      member_role.rolname,
      grantor_role.rolname
    ) AS statement
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted_role
      ON granted_role.oid = membership.roleid
    JOIN pg_catalog.pg_roles AS member_role
      ON member_role.oid = membership.member
    JOIN pg_catalog.pg_roles AS grantor_role
      ON grantor_role.oid = membership.grantor
    WHERE member_role.rolname = ${specification.login}
  `;
  for (const membership of staleMemberships) {
    if (membership.statement === undefined) {
      throw Object.assign(new Error("role revocation generation failed"), {
        code: "ROLE_STATEMENT_FAILED",
      });
    }
    // eslint-disable-next-line no-await-in-loop -- Finish each ordered revocation before granting the canonical membership.
    await transaction.unsafe(membership.statement);
  }
  await transaction.unsafe(grantRole.statement);
}
