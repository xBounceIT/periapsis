import { readFileSync } from "node:fs";
import postgres from "postgres";

import { requireDatabaseUrl } from "./database-url.js";

const runtimeRoles = [
  {
    connectionLimit: 40,
    group: "periapsis_api",
    login: "periapsis_api_login",
    secret: "PERIAPSIS_API_DATABASE_PASSWORD",
  },
  {
    connectionLimit: 20,
    group: "periapsis_worker",
    login: "periapsis_worker_login",
    secret: "PERIAPSIS_WORKER_DATABASE_PASSWORD",
  },
  {
    connectionLimit: 20,
    group: "periapsis_notifier",
    login: "periapsis_notifier_login",
    secret: "PERIAPSIS_NOTIFIER_DATABASE_PASSWORD",
  },
  {
    connectionLimit: -1,
    group: "periapsis_auditor",
    login: "periapsis_auditor_login",
    secret: "PERIAPSIS_AUDITOR_DATABASE_PASSWORD",
  },
] as const;

type RuntimeRole = (typeof runtimeRoles)[number];
type RuntimeRoleCredential = {
  password: string;
  role: RuntimeRole;
};

const webhookPlainLocalOptIn = requireWebhookPlainLocalOptIn();

const client = postgres(requireDatabaseUrl(), {
  max: 1,
  onnotice: () => undefined,
});

try {
  const credentials = runtimeRoles.map((role) => ({
    password: requireSecret(role.secret),
    role,
  }));

  await client.begin(async (transaction) => {
    await provisionRuntimeRolesSequentially(transaction, credentials);
    await provisionWebhookPlainLocalRoleOptIns(
      transaction,
      webhookPlainLocalOptIn,
    );
  });
} finally {
  await client.end();
}

async function provisionRuntimeRolesSequentially(
  transaction: postgres.TransactionSql,
  credentials: readonly RuntimeRoleCredential[],
  index = 0,
): Promise<void> {
  const credential = credentials[index];
  if (credential === undefined) {
    return;
  }

  await provisionRuntimeRole(transaction, credential);
  await provisionRuntimeRolesSequentially(transaction, credentials, index + 1);
}

async function provisionRuntimeRole(
  transaction: postgres.TransactionSql,
  credential: RuntimeRoleCredential,
): Promise<void> {
  const [{ quoted }] = await transaction<[{ quoted: string }]>`
    SELECT quote_literal(${credential.password}) AS quoted
  `;

  const existing = await transaction<{ exists: boolean }[]>`
    SELECT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles
      WHERE rolname = ${credential.role.login}
    ) AS exists
  `;

  if (existing[0]?.exists === true) {
    await transaction.unsafe(
      `ALTER ROLE ${quoteIdentifier(credential.role.login)} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT ${credential.role.connectionLimit} VALID UNTIL 'infinity' PASSWORD ${quoted}`,
    );
  } else {
    await transaction.unsafe(
      `CREATE ROLE ${quoteIdentifier(credential.role.login)} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT ${credential.role.connectionLimit} VALID UNTIL 'infinity' PASSWORD ${quoted}`,
    );
  }

  await transaction.unsafe(
    `ALTER ROLE ${quoteIdentifier(credential.role.login)} RESET ALL`,
  );

  const directMemberships = await transaction<
    { grantorName: string; roleName: string }[]
  >`
    SELECT granted_role.rolname AS "roleName",
           grantor_role.rolname AS "grantorName"
    FROM pg_catalog.pg_auth_members AS membership
    INNER JOIN pg_catalog.pg_roles AS member_role
      ON member_role.oid = membership.member
    INNER JOIN pg_catalog.pg_roles AS granted_role
      ON granted_role.oid = membership.roleid
    INNER JOIN pg_catalog.pg_roles AS grantor_role
      ON grantor_role.oid = membership.grantor
    WHERE member_role.rolname = ${credential.role.login}
    ORDER BY granted_role.rolname, grantor_role.rolname
  `;

  const revokeStatements = directMemberships.map(
    (membership) =>
      `REVOKE ${quoteIdentifier(membership.roleName)} FROM ${quoteIdentifier(credential.role.login)} GRANTED BY ${quoteIdentifier(membership.grantorName)} CASCADE`,
  );
  if (revokeStatements.length > 0) {
    await transaction.unsafe(revokeStatements.join(";\n"));
  }

  await transaction.unsafe(
    `GRANT ${quoteIdentifier(credential.role.group)} TO ${quoteIdentifier(credential.role.login)} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`,
  );
}

async function provisionWebhookPlainLocalRoleOptIns(
  transaction: postgres.TransactionSql,
  enabled: boolean,
): Promise<void> {
  const [surface] = await transaction<[{ exists: boolean }]>`
    SELECT pg_catalog.to_regclass(
      'public.webhook_plain_local_runtime_role_opt_ins'
    ) IS NOT NULL AS exists
  `;
  if (!surface.exists) {
    return;
  }

  await upsertWebhookPlainLocalRoleOptIn(
    transaction,
    "periapsis_api_login",
    enabled,
  );
  await upsertWebhookPlainLocalRoleOptIn(
    transaction,
    "periapsis_notifier_login",
    enabled,
  );
}

async function upsertWebhookPlainLocalRoleOptIn(
  transaction: postgres.TransactionSql,
  roleName: "periapsis_api_login" | "periapsis_notifier_login",
  enabled: boolean,
): Promise<void> {
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
    WHERE current_opt_in.enabled
      IS DISTINCT FROM EXCLUDED.enabled
  `;
}

function requireWebhookPlainLocalOptIn(): boolean {
  const environment = process.env["PERIAPSIS_ENV"] ?? "production";
  if (
    environment !== "development" &&
    environment !== "test" &&
    environment !== "production"
  ) {
    throw new Error("PERIAPSIS_ENV must be development, test, or production");
  }
  const raw = process.env["PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL"] ?? "false";
  if (raw !== "true" && raw !== "false") {
    throw new Error(
      "PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL must be true or false",
    );
  }
  const enabled = raw === "true";
  if (enabled && environment === "production") {
    throw new Error(
      "PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL cannot be enabled in production",
    );
  }
  return enabled;
}

function requireSecret(name: string): string {
  const file = process.env[`${name}_FILE`];
  const value =
    file === undefined || file.trim() === ""
      ? process.env[name]
      : readFileSync(file, "utf8");

  if (value === undefined || value.trim() === "") {
    throw new Error(`${name} or ${name}_FILE is required`);
  }
  if (value.includes("\u0000")) {
    throw new Error(`${name} contains an invalid null byte`);
  }
  return value.trim();
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}
