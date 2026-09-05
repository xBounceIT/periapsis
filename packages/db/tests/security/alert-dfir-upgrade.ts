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

const validDatabaseUrl =
  process.env.PERIAPSIS_ALERT_DFIR_UPGRADE_TEST_DATABASE_URL;
const invalidDatabaseUrl =
  process.env.PERIAPSIS_ALERT_DFIR_INVALID_UPGRADE_TEST_DATABASE_URL;
if (!validDatabaseUrl || !invalidDatabaseUrl) {
  throw new Error(
    "Alert DFIR upgrade tests require two empty isolated PostgreSQL 18 databases",
  );
}
const validDatabaseConnectionString: string = validDatabaseUrl;
const invalidDatabaseConnectionString: string = invalidDatabaseUrl;
assert.notEqual(
  validDatabaseConnectionString,
  invalidDatabaseConnectionString,
  "the valid and invalid Alert DFIR upgrade paths require distinct databases",
);

const validConnection = new URL(validDatabaseConnectionString);
const invalidConnection = new URL(invalidDatabaseConnectionString);
const databaseName = (connection: URL): string =>
  decodeURIComponent(connection.pathname.replace(/^\//u, ""));
const validDatabaseName = databaseName(validConnection);
const invalidDatabaseName = databaseName(invalidConnection);
for (const [label, name] of [
  ["valid", validDatabaseName],
  ["invalid", invalidDatabaseName],
] as const) {
  assert.match(
    name,
    /^(?!postgres$|template[01]$)[A-Za-z][A-Za-z0-9_-]{0,62}$/u,
    `${label} Alert DFIR database name is unsafe`,
  );
}
for (const field of [
  "protocol",
  "hostname",
  "port",
  "username",
  "password",
] as const) {
  assert.equal(
    invalidConnection[field],
    validConnection[field],
    `Alert DFIR database URLs differ by ${field}`,
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4a26-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  user: uuid(2),
  membership: uuid(3),
  firstCase: uuid(4),
  secondCase: uuid(5),
  relationship: uuid(6),
} as const;

let valid = postgres(validDatabaseConnectionString, {
  max: 1,
  onnotice: () => undefined,
});
let invalid: Sql | undefined;
const migrationsRoot = resolve(import.meta.dirname, "../../migrations");

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

const journal = parseJournal(
  await readFile(resolve(migrationsRoot, "meta/_journal.json"), "utf8"),
);
const predecessorIndex = journal.entries.findIndex(
  (entry) => entry.tag === "0225_custom_field_bulk_import",
);
const targetIndex = journal.entries.findIndex(
  (entry) => entry.tag === "0226_alert_dfir_completion",
);
const target = journal.entries[targetIndex];
assert(predecessorIndex >= 0, "0225 predecessor is absent from the journal");
assert(target, "0226 Alert DFIR migration is absent from the journal");
assert.equal(target.idx, journal.entries[predecessorIndex]!.idx + 1);

const predecessorEntries = journal.entries.slice(0, predecessorIndex + 1);
const stageRoot = await mkdtemp(join(tmpdir(), "periapsis-alert-dfir-0225-"));

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function clonePredecessorDatabase(): Promise<void> {
  const emptyInvalid = postgres(invalidDatabaseConnectionString, {
    max: 1,
    onnotice: () => undefined,
  });
  try {
    const [surface] = await emptyInvalid<{ relation_count: number }[]>`
      SELECT count(*)::integer AS relation_count
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname NOT IN (
        'pg_catalog','information_schema','pg_toast'
      )
        AND relation.relkind IN ('r','p','v','m','S','f')
    `;
    assert.equal(
      surface?.relation_count,
      0,
      "the isolated invalid Alert DFIR upgrade database must be empty",
    );
  } finally {
    await emptyInvalid.end({ timeout: 5 });
  }

  await valid.end({ timeout: 5 });
  const maintenanceConnection = new URL(validConnection);
  maintenanceConnection.pathname = "/postgres";
  const maintenance = postgres(maintenanceConnection.toString(), {
    max: 1,
    onnotice: () => undefined,
  });
  try {
    await maintenance.unsafe(
      `DROP DATABASE ${quoteIdentifier(invalidDatabaseName)}`,
    );
    await maintenance.unsafe(
      `CREATE DATABASE ${quoteIdentifier(invalidDatabaseName)} TEMPLATE ${quoteIdentifier(validDatabaseName)}`,
    );
  } finally {
    await maintenance.end({ timeout: 5 });
  }
  valid = postgres(validDatabaseConnectionString, {
    max: 1,
    onnotice: () => undefined,
  });
  invalid = postgres(invalidDatabaseConnectionString, {
    max: 1,
    onnotice: () => undefined,
  });
}

async function prepareMigrationStage(): Promise<void> {
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
  await migrate(drizzle(valid), { migrationsFolder: stageRoot });
  await clonePredecessorDatabase();
  await copyFile(
    resolve(migrationsRoot, `${target!.tag}.sql`),
    resolve(stageRoot, `${target!.tag}.sql`),
  );
  await writeFile(
    resolve(stageRoot, "meta/_journal.json"),
    `${JSON.stringify({ ...journal, entries: journal.entries.slice(0, targetIndex + 1) }, null, 2)}\n`,
  );
}

async function prepare0225Database(
  client: Sql,
  caseToCase: boolean,
): Promise<void> {
  const suffix = `${sequence.toString(36)}-${caseToCase ? "invalid" : "valid"}`;
  await client.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name)
      VALUES (${fixture.tenant}::uuid,${`alert-dfir-upgrade-${suffix}`},'Alert DFIR upgrade')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id)
      VALUES (${fixture.tenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      VALUES (
        ${fixture.user}::uuid,
        ${`alert-dfir-upgrade-${suffix}@example.invalid`},
        'Upgrade actor',true
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status)
      VALUES (
        ${fixture.membership}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,'tenant_admin','active'
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.membership}::uuid
      )
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    const insertCase = async (id: string, number: string): Promise<void> => {
      await transaction`
        INSERT INTO public.cases(
          id,tenant_id,number,workflow_id,workflow_version,state_key,
          title,created_by_membership_id,created_by_user_id,version,updated_at
        )
        SELECT ${id}::uuid,${fixture.tenant}::uuid,${number},workflow.id,
               workflow.current_version,state.value->>'key','Legacy Case',
               ${fixture.membership}::uuid,${fixture.user}::uuid,1,
               transaction_timestamp()
        FROM public.ticket_workflows AS workflow
        JOIN public.ticket_workflow_versions AS version
          ON version.tenant_id=workflow.tenant_id
         AND version.workflow_id=workflow.id
         AND version.aggregate_kind=workflow.aggregate_kind
         AND version.version=workflow.current_version
        CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
        WHERE workflow.tenant_id=${fixture.tenant}::uuid
          AND workflow.key='default_case'
          AND (state.value->>'initial')::boolean
      `;
    };
    await insertCase(fixture.firstCase, "CAS-2099-990001");
    await insertCase(fixture.secondCase, "CAS-2099-990002");
    if (caseToCase) {
      await transaction`
        INSERT INTO public.dfir_relationships(
          id,tenant_id,source_kind,source_id,target_kind,target_id,
          relationship_type,created_by_membership_id
        ) VALUES (
          ${fixture.relationship}::uuid,${fixture.tenant}::uuid,
          'case',${fixture.firstCase}::uuid,'case',${fixture.secondCase}::uuid,
          'contains',${fixture.membership}::uuid
        )
      `;
    } else {
      await transaction`
        INSERT INTO public.dfir_relationships(
          id,tenant_id,source_kind,source_id,target_kind,
          target_external_type,target_external_id,relationship_type,
          created_by_membership_id
        ) VALUES (
          ${fixture.relationship}::uuid,${fixture.tenant}::uuid,
          'case',${fixture.firstCase}::uuid,'external','url',
          'https://example.invalid/legacy','references',
          ${fixture.membership}::uuid
        )
      `;
    }
  });
}

try {
  const [initialServer] = await valid<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    initialServer?.version.startsWith("18."),
    "upgrade harness requires PostgreSQL 18",
  );
  await prepareMigrationStage();
  assert(invalid, "invalid predecessor database was not cloned");
  const predecessors = await Promise.all(
    [valid, invalid].map(async (client) => {
      const [predecessor] = await client<{ latest: string; count: number }[]>`
        SELECT max(created_at)::text AS latest,count(*)::integer AS count
        FROM drizzle.__drizzle_migrations
      `;
      return predecessor;
    }),
  );
  for (const predecessor of predecessors) {
    assert.equal(
      predecessor?.latest,
      String(journal.entries[predecessorIndex]!.when),
    );
    assert.equal(predecessor?.count, predecessorEntries.length);
  }

  await prepare0225Database(valid, false);
  await prepare0225Database(invalid, true);

  await migrate(drizzle(valid), { migrationsFolder: stageRoot });
  const [backfilled] = await valid<{ case_id: string; version: string }[]>`
    SELECT case_id::text,version::text
    FROM public.dfir_relationships
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.relationship}::uuid
  `;
  assert.equal(backfilled?.case_id, fixture.firstCase);
  assert.equal(backfilled?.version, "1");
  const [ready] = await valid<{ ready: boolean }[]>`
    SELECT app.alert_dfir_runtime_schema_readiness_v2() AS ready
  `;
  assert.equal(ready?.ready, true);

  await assert.rejects(
    migrate(drizzle(invalid), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal(sqlState(error), "23514");
      return true;
    },
    "0226 accepted an ambiguous Case-to-Case legacy root",
  );
  const [rolledBack] = await invalid<{ exists: boolean; applied: boolean }[]>`
    SELECT
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid='public.dfir_relationships'::regclass
          AND attname='case_id' AND NOT attisdropped
      ) AS exists,
      EXISTS (
        SELECT 1 FROM drizzle.__drizzle_migrations
        WHERE created_at=${target.when}
      ) AS applied
  `;
  assert.equal(rolledBack?.exists, false, "failed 0226 left partial columns");
  assert.equal(rolledBack?.applied, false, "failed 0226 was journaled");

  await invalid`
    DELETE FROM public.dfir_relationships
    WHERE tenant_id=${fixture.tenant}::uuid
      AND id=${fixture.relationship}::uuid
  `;
  await invalid`
    INSERT INTO public.dfir_relationships(
      id,tenant_id,source_kind,source_external_type,source_external_id,
      target_kind,target_external_type,target_external_id,relationship_type,
      created_by_membership_id
    ) VALUES (
      ${fixture.relationship}::uuid,${fixture.tenant}::uuid,
      'external','url','https://source.example.invalid/legacy',
      'external','url','https://target.example.invalid/legacy','references',
      ${fixture.membership}::uuid
    )
  `;
  await assert.rejects(
    migrate(drizzle(invalid), { migrationsFolder: stageRoot }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.equal(sqlState(error), "23514");
      return true;
    },
    "0226 accepted a legacy relationship with no Case root",
  );
  const [zeroCaseRolledBack] = await invalid<
    { exists: boolean; applied: boolean }[]
  >`
    SELECT EXISTS (
      SELECT 1 FROM pg_catalog.pg_attribute
      WHERE attrelid='public.dfir_relationships'::regclass
        AND attname='case_id' AND NOT attisdropped
    ) AS exists,
    EXISTS (
      SELECT 1 FROM drizzle.__drizzle_migrations
      WHERE created_at=${target.when}
    ) AS applied
  `;
  assert.deepEqual(
    zeroCaseRolledBack,
    { exists: false, applied: false },
    "second failed 0226 preflight left partial schema or journal state",
  );
  process.stdout.write("Alert DFIR 0225 to 0226 upgrade checks passed\n");
} finally {
  await Promise.all([
    valid.end({ timeout: 5 }),
    invalid?.end({ timeout: 5 }),
    rm(stageRoot, { recursive: true, force: true }),
  ]);
}
