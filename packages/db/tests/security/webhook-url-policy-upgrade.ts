import assert from "node:assert/strict";
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
import postgres, { type Sql } from "postgres";

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

const databaseUrl =
  process.env.PERIAPSIS_WEBHOOK_URL_POLICY_UPGRADE_TEST_DATABASE_URL;
if (!databaseUrl?.trim()) {
  throw new Error(
    "PERIAPSIS_WEBHOOK_URL_POLICY_UPGRADE_TEST_DATABASE_URL must name an isolated PostgreSQL 18 database that is empty or migrated exactly through 0226",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7b10-2700-7000-8000-${(sequence + BigInt(offset)).toString(16).padStart(12, "0")}`;
const ids = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  secret: uuid(4),
  invalidConfiguration: uuid(5),
  excessiveConfiguration: uuid(6),
  httpsConfiguration: uuid(7),
  localConfiguration: uuid(8),
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sqlState(error: unknown): string | undefined {
  let current = error;
  for (let depth = 0; depth < 4 && isRecord(current); depth += 1) {
    if (typeof current.code === "string") return current.code;
    current = current.cause;
  }
  return undefined;
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

const packageRoot = resolve(import.meta.dirname, "../..");
const migrationsRoot = resolve(packageRoot, "migrations");
const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = journal.entries.findIndex(
  (entry) => entry.tag === "0226_alert_dfir_completion",
);
const targetIndex = journal.entries.findIndex(
  (entry) => entry.tag === "0227_tenant_webhook_url_policy",
);
const target = journal.entries[targetIndex];
assert(predecessorIndex >= 0, "0226 predecessor is absent from the journal");
assert(target, "0227 webhook URL policy migration is absent from the journal");
assert.equal(target.idx, journal.entries[predecessorIndex]!.idx + 1);

const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const stageRoot = await mkdtemp(
  join(tmpdir(), "periapsis-webhook-policy-0226-"),
);
const sql = postgres(databaseUrl, { max: 1, onnotice: () => undefined });

async function stagePredecessor(): Promise<void> {
  await mkdir(resolve(stageRoot, "meta"));
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: predecessorEntries }, null, 2)}\n`,
  );
  await Promise.all(
    predecessorEntries.map((entry) =>
      copyFile(
        resolve(migrationsRoot, `${entry.tag}.sql`),
        resolve(stageRoot, `${entry.tag}.sql`),
      ),
    ),
  );
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });
}

async function stageTarget(): Promise<void> {
  await copyFile(
    resolve(migrationsRoot, `${target!.tag}.sql`),
    resolve(stageRoot, `${target!.tag}.sql`),
  );
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: journal.entries.slice(0, targetIndex + 1) }, null, 2)}\n`,
  );
}

async function insertIdentityAndSecret(): Promise<void> {
  const suffix = sequence.toString(36);
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name)
      VALUES (${ids.tenant}::uuid,${`webhook-upgrade-${suffix}`},'Webhook upgrade')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES (${ids.tenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      VALUES (${ids.user}::uuid,${`webhook-upgrade-${suffix}@example.invalid`},
              'Webhook upgrade actor',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status)
      VALUES (${ids.membership}::uuid,${ids.tenant}::uuid,${ids.user}::uuid,
              'tenant_admin','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${ids.tenant}::uuid,${ids.membership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_secret_versions(
        tenant_id,secret_id,version,kind,key_version,nonce,ciphertext,
        created_by_membership_id,created_by_user_id
      ) VALUES (
        ${ids.tenant}::uuid,${ids.secret}::uuid,1,'webhook_signing_key',1,
        decode(repeat('11',12),'hex'),decode(repeat('22',17),'hex'),
        ${ids.membership}::uuid,${ids.user}::uuid
      )
    `;
  });
}

async function insertConfiguration(
  client: Sql,
  configurationID: string,
  urls: readonly string[],
): Promise<void> {
  await client`
    INSERT INTO public.tenant_notification_webhook_configurations(
      id,tenant_id,current_version,created_by_membership_id,created_by_user_id
    ) VALUES (
      ${configurationID}::uuid,${ids.tenant}::uuid,${urls.length},
      ${ids.membership}::uuid,${ids.user}::uuid
    )
  `;
  await Promise.all(
    urls.map(
      (endpoint, index) =>
        client`
        INSERT INTO public.tenant_notification_webhook_configuration_versions(
          tenant_id,configuration_id,version,name,endpoint_url,event_types,
          audience,signing_secret_id,signing_secret_version,timeout_ms,enabled,
          created_by_membership_id,created_by_user_id
        ) VALUES (
          ${ids.tenant}::uuid,${configurationID}::uuid,${index + 1},
          ${`Legacy webhook ${index + 1}`},${endpoint},
          ARRAY['alert.created']::public.notification_event_type[],'operator',
          ${ids.secret}::uuid,1,5000,true,
          ${ids.membership}::uuid,${ids.user}::uuid
        )
      `,
    ),
  );
}

async function insertExcessiveConfiguration(): Promise<void> {
  await sql`
    INSERT INTO public.tenant_notification_webhook_configurations(
      id,tenant_id,current_version,created_by_membership_id,created_by_user_id
    ) VALUES (
      ${ids.excessiveConfiguration}::uuid,${ids.tenant}::uuid,257,
      ${ids.membership}::uuid,${ids.user}::uuid
    )
  `;
  await sql`
    INSERT INTO public.tenant_notification_webhook_configuration_versions(
      tenant_id,configuration_id,version,name,endpoint_url,event_types,
      audience,signing_secret_id,signing_secret_version,timeout_ms,enabled,
      created_by_membership_id,created_by_user_id
    )
    SELECT ${ids.tenant}::uuid,${ids.excessiveConfiguration}::uuid,series,
           'Excessive legacy webhook ' || series,
           'https://hook-' || lpad(series::text,3,'0') || '.example.invalid/',
           ARRAY['alert.created']::public.notification_event_type[],'operator',
           ${ids.secret}::uuid,1,5000,true,
           ${ids.membership}::uuid,${ids.user}::uuid
    FROM generate_series(1,257) AS series
  `;
}

async function removeConfiguration(configurationID: string): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction.unsafe(
      "ALTER TABLE public.tenant_notification_webhook_configuration_versions DISABLE TRIGGER tenant_notification_webhook_versions_immutable_v1",
    );
    await transaction`
      DELETE FROM public.tenant_notification_webhook_configuration_versions
      WHERE tenant_id=${ids.tenant}::uuid
        AND configuration_id=${configurationID}::uuid
    `;
    await transaction.unsafe(
      "ALTER TABLE public.tenant_notification_webhook_configuration_versions ENABLE TRIGGER tenant_notification_webhook_versions_immutable_v1",
    );
    await transaction`
      DELETE FROM public.tenant_notification_webhook_configurations
      WHERE tenant_id=${ids.tenant}::uuid
        AND id=${configurationID}::uuid
    `;
  });
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18."),
    "upgrade harness requires PostgreSQL 18",
  );
  await stagePredecessor();
  const [predecessor] = await sql<{ latest: string; count: number }[]>`
    SELECT max(created_at)::text AS latest,count(*)::integer AS count
    FROM drizzle.__drizzle_migrations
  `;
  assert.equal(
    predecessor?.latest,
    String(journal.entries[predecessorIndex]!.when),
  );
  assert.equal(predecessor?.count, predecessorEntries.length);

  await insertIdentityAndSecret();
  await stageTarget();
  await insertConfiguration(sql, ids.invalidConfiguration, [
    "http://10.0.0.1/private",
  ]);
  await assert.rejects(
    migrate(drizzle(sql), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal(sqlState(error), "42501");
      return true;
    },
    "0227 silently accepted a legacy non-loopback HTTP destination",
  );
  const [rolledBack] = await sql<
    { column_exists: boolean; applied: boolean }[]
  >`
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute
      WHERE attrelid='public.tenant_notification_webhook_configuration_versions'::regclass
        AND attname='endpoint_canonical_url' AND NOT attisdropped
    ) AS column_exists,
    EXISTS (
      SELECT 1 FROM drizzle.__drizzle_migrations
      WHERE created_at=${target.when}
    ) AS applied
  `;
  assert.deepEqual(
    rolledBack,
    { column_exists: false, applied: false },
    "failed 0227 preflight left partial schema or journal state",
  );
  await removeConfiguration(ids.invalidConfiguration);

  await insertExcessiveConfiguration();
  await assert.rejects(
    migrate(drizzle(sql), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal(sqlState(error), "54000");
      return true;
    },
    "0227 silently truncated more than 256 historical HTTPS destinations",
  );
  await removeConfiguration(ids.excessiveConfiguration);

  await insertConfiguration(sql, ids.httpsConfiguration, [
    "https://Legacy.Example.com:443/hooks?x=1",
    "https://pending.example.com/notify",
  ]);
  await insertConfiguration(sql, ids.localConfiguration, [
    "http://localhost:8080/hook",
  ]);
  await migrate(drizzle(sql), { migrationsFolder: stageRoot });

  const rows = await sql<
    {
      configuration_id: string;
      version: number;
      endpoint_url: string;
      endpoint_canonical_url: string;
      endpoint_digest_valid: boolean;
      policy_id: string | null;
      policy_version_id: string | null;
      policy_version: number | null;
      policy_digest_valid: boolean;
      local: boolean;
    }[]
  >`
    SELECT config.configuration_id::text,config.version,config.endpoint_url,
           config.endpoint_canonical_url,
           config.endpoint_digest = canonical.endpoint_digest AS endpoint_digest_valid,
           config.webhook_url_policy_id::text AS policy_id,
           config.webhook_url_policy_version_id::text AS policy_version_id,
           config.webhook_url_policy_version AS policy_version,
           config.webhook_url_policy_digest IS NOT DISTINCT FROM policy.policy_digest
             AS policy_digest_valid,
           config.local_development_exemption AS local
    FROM public.tenant_notification_webhook_configuration_versions AS config
    CROSS JOIN LATERAL app.private_canonical_webhook_endpoint_v1(
      config.endpoint_url,true
    ) AS canonical
    LEFT JOIN public.tenant_webhook_url_policy_versions AS policy
      ON policy.tenant_id=config.tenant_id
     AND policy.policy_id=config.webhook_url_policy_id
     AND policy.id=config.webhook_url_policy_version_id
     AND policy.version=config.webhook_url_policy_version
    WHERE config.tenant_id=${ids.tenant}::uuid
    ORDER BY configuration_id,version
  `;
  assert.deepEqual(
    [...rows],
    [
      {
        configuration_id: ids.httpsConfiguration,
        version: 1,
        endpoint_url: "https://legacy.example.com/hooks?x=1",
        endpoint_canonical_url: "https://legacy.example.com/hooks?x=1",
        endpoint_digest_valid: true,
        policy_id: rows[0]?.policy_id ?? null,
        policy_version_id: rows[0]?.policy_version_id ?? null,
        policy_version: 1,
        policy_digest_valid: true,
        local: false,
      },
      {
        configuration_id: ids.httpsConfiguration,
        version: 2,
        endpoint_url: "https://pending.example.com/notify",
        endpoint_canonical_url: "https://pending.example.com/notify",
        endpoint_digest_valid: true,
        policy_id: rows[0]?.policy_id ?? null,
        policy_version_id: rows[0]?.policy_version_id ?? null,
        policy_version: 1,
        policy_digest_valid: true,
        local: false,
      },
      {
        configuration_id: ids.localConfiguration,
        version: 1,
        endpoint_url: "http://localhost:8080/hook",
        endpoint_canonical_url: "http://localhost:8080/hook",
        endpoint_digest_valid: true,
        policy_id: null,
        policy_version_id: null,
        policy_version: null,
        policy_digest_valid: true,
        local: true,
      },
    ].toSorted((left, right) =>
      left.configuration_id < right.configuration_id
        ? -1
        : left.configuration_id > right.configuration_id
          ? 1
          : left.version - right.version,
    ),
  );
  assert(rows[0]?.policy_id, "HTTPS backfill did not create a tenant policy");
  assert(
    rows[0]?.policy_version_id,
    "HTTPS backfill did not pin a policy version",
  );

  const [policy] = await sql<
    { rules: unknown; versions: number; applied: boolean }[]
  >`
    SELECT version.rules,
           (SELECT count(*)::integer
            FROM public.tenant_webhook_url_policy_versions
            WHERE tenant_id=${ids.tenant}::uuid) AS versions,
           EXISTS (
             SELECT 1 FROM drizzle.__drizzle_migrations
             WHERE created_at=${target.when}
           ) AS applied
    FROM public.tenant_webhook_url_policy_versions AS version
    WHERE version.tenant_id=${ids.tenant}::uuid AND version.version=1
  `;
  assert.deepEqual(policy, {
    rules: [
      {
        effect: "allow",
        match: "exact",
        hostname: "legacy.example.com",
        port: 443,
      },
      {
        effect: "allow",
        match: "exact",
        hostname: "pending.example.com",
        port: 443,
      },
    ],
    versions: 1,
    applied: true,
  });

  process.stdout.write("webhook URL policy rolling-upgrade checks passed\n");
} finally {
  await Promise.all([
    sql.end({ timeout: 5 }),
    rm(stageRoot, { recursive: true, force: true }),
  ]);
}
