import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { SQL } from "drizzle-orm";
import { getTableConfig, PgDialect } from "drizzle-orm/pg-core";
import postgres, { type TransactionSql } from "postgres";

import {
  dfirMutationCommandResults,
  dfirMutationCommands,
  dfirMutationReplayKeys,
  dfirMutationResourceIds,
  dfirTicketCommandRetentions,
} from "../../src/schema/dfir.js";
import { dfirSharedResourceLinkEvents } from "../../src/schema/dfir-shared-resources.js";

type ErrorWithCode = Error & { code?: string };
type CleanupCounts = {
  commands_deleted: string;
  results_deleted: string;
};
type CatalogColumn = {
  column_name: string;
  not_null: boolean;
  ordinal: number;
  sql_type: string;
  table_name: string;
};
type CatalogConstraint = {
  columns: string[];
  constraint_kind: "p" | "u";
  name: string;
  table_name: string;
};
type CatalogForeignKey = {
  columns: string[];
  delete_action: string;
  foreign_columns: string[];
  foreign_schema: string;
  foreign_table: string;
  name: string;
  table_name: string;
  update_action: string;
};
type CatalogUniqueIndex = {
  access_method: string;
  attribute_count: number;
  is_live: boolean;
  is_ready: boolean;
  is_unique: boolean;
  is_valid: boolean;
  key_count: number;
  key_definitions: string[];
  name: string;
  nulls_not_distinct: boolean;
  options: string[];
  predicate: string | null;
  table_name: string;
};

const canonicalReceiptTables = [
  dfirMutationCommands,
  dfirMutationCommandResults,
  dfirMutationResourceIds,
  dfirMutationReplayKeys,
  dfirTicketCommandRetentions,
  dfirSharedResourceLinkEvents,
] as const;

const databaseUrl =
  process.env.PERIAPSIS_DFIR_MUTATION_RETENTION_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_DFIR_MUTATION_RETENTION_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4af0-1000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const hour = 60 * 60 * 1000;
const now = Date.now();

const fixture = {
  tenant: uuid(1),
  user: uuid(101),
  membership: uuid(201),
  alert: uuid(301),
  case: uuid(302),
  audit: uuid(401),
  activity: uuid(402),
  outbox: uuid(403),
  genericLockedCommand: uuid(501),
  genericOtherCommand: uuid(502),
  genericActiveCommand: uuid(503),
  genericMaximumCommand: uuid(504),
  genericLockedResource: uuid(511),
  genericOtherResource: uuid(512),
  genericActiveResource: uuid(513),
  genericMaximumResource: uuid(514),
  alertExpiredCommand: uuid(601),
  alertActiveCommand: uuid(602),
  alertMaximumCommand: uuid(603),
  alertExpiredTask: uuid(611),
  alertActiveTask: uuid(612),
  alertMaximumTask: uuid(613),
  alertExpiredChecklistItem: uuid(621),
  alertActiveChecklistItem: uuid(622),
  alertMaximumChecklistItem: uuid(623),
  caseExpiredCommand: uuid(701),
  caseActiveCommand: uuid(702),
  caseMaximumCommand: uuid(703),
  nonDfirTicketCommand: uuid(704),
  caseExpiredTask: uuid(711),
  caseActiveTask: uuid(712),
  caseMaximumTask: uuid(713),
  caseExpiredChecklistItem: uuid(721),
  caseActiveChecklistItem: uuid(722),
  caseMaximumChecklistItem: uuid(723),
  checklistTask: uuid(801),
  checklistItem: uuid(802),
  relationship: uuid(901),
  retraction: uuid(902),
  sharedIoc: uuid(1001),
  sharedLinkEvent: uuid(1002),
  sharedLinkCommand: uuid(1003),
  reservedCaseCommand: uuid(1301),
  reservedCaseTask: uuid(1302),
  reservedCaseChecklist: uuid(1303),
} as const;

const primary = postgres(databaseUrl, { max: 4, onnotice: () => undefined });
const contender = postgres(databaseUrl, {
  max: 2,
  onnotice: () => undefined,
});

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`dfir-mutation-retention:${label}`)
    .digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function expectSqlState(
  operation: Promise<unknown>,
  expected: string,
  message: string,
): Promise<void> {
  await assert.rejects(
    operation,
    (error) => assertSqlState(error, expected),
    message,
  );
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function renderModelSql(
  dialect: PgDialect,
  tableName: string,
  purpose: string,
  expression: SQL,
): string {
  const rendered = dialect.sqlToQuery(expression, "indexes");
  assert.equal(
    rendered.params.length,
    0,
    `${tableName} ${purpose} cannot contain DDL parameters`,
  );
  return rendered.sql;
}

function renderIndexKey(
  dialect: PgDialect,
  tableName: string,
  column: unknown,
): string {
  if (column instanceof SQL) {
    return `(${renderModelSql(dialect, tableName, "index expression", column)})`;
  }
  if (
    typeof column !== "object" ||
    column === null ||
    !("name" in column) ||
    typeof column.name !== "string" ||
    !("indexConfig" in column) ||
    typeof column.indexConfig !== "object" ||
    column.indexConfig === null
  ) {
    throw new Error(`${tableName} has an unsupported canonical index key`);
  }
  const config = column.indexConfig as {
    nulls?: "first" | "last";
    opClass?: string;
    order?: "asc" | "desc";
  };
  let definition = quoteIdentifier(column.name);
  if (config.opClass !== undefined) {
    assert.match(
      config.opClass,
      /^[A-Za-z_][A-Za-z0-9_]*$/,
      `${tableName} has an invalid canonical index operator class`,
    );
    definition += ` ${quoteIdentifier(config.opClass)}`;
  }
  if (config.order === "desc") {
    definition += " DESC";
  }
  const defaultNulls = config.order === "desc" ? "first" : "last";
  if (config.nulls !== undefined && config.nulls !== defaultNulls) {
    definition += ` NULLS ${config.nulls.toUpperCase()}`;
  }
  return definition;
}

function renderIndexStorageOptions(
  tableName: string,
  options: Record<string, unknown> | undefined,
): string {
  if (options === undefined || Object.keys(options).length === 0) {
    return "";
  }
  return ` WITH (${Object.entries(options)
    .map(([name, value]) => {
      assert.match(
        name,
        /^[A-Za-z_][A-Za-z0-9_]*$/,
        `${tableName} has an invalid canonical index storage option`,
      );
      assert(
        typeof value === "string" ||
          typeof value === "number" ||
          typeof value === "boolean",
        `${tableName}.${name} has an unsupported index storage value`,
      );
      const renderedValue =
        typeof value === "number" ? String(value) : quoteLiteral(String(value));
      return `${quoteIdentifier(name)}=${renderedValue}`;
    })
    .join(",")})`;
}

function byTableAndName<T extends { name: string; table_name: string }>(
  left: T,
  right: T,
): number {
  return (
    left.table_name.localeCompare(right.table_name) ||
    left.name.localeCompare(right.name)
  );
}

async function inRolledBackTransaction<T>(
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const rollbackSignal = new Error("canonical index shadow rollback");
  let completed = false;
  let outcome: { value: T } | undefined;
  try {
    await primary.begin(async (transaction) => {
      outcome = { value: await operation(transaction) };
      completed = true;
      throw rollbackSignal;
    });
  } catch (error) {
    if (error !== rollbackSignal) {
      throw error;
    }
  }
  assert(completed, "canonical index shadow transaction did not complete");
  assert(outcome, "canonical index shadow result is unavailable");
  return outcome.value;
}

async function readUniqueIndexCatalog(
  transaction: TransactionSql,
  tableNames: readonly string[],
  temporary: boolean,
): Promise<CatalogUniqueIndex[]> {
  const rows = await transaction<CatalogUniqueIndex[]>`
    SELECT relation.relname AS table_name,
           index_relation.relname AS name,
           access_method.amname AS access_method,
           index_row.indisunique AS is_unique,
           index_row.indisvalid AS is_valid,
           index_row.indisready AS is_ready,
           index_row.indislive AS is_live,
           index_row.indnullsnotdistinct AS nulls_not_distinct,
           index_row.indnkeyatts::integer AS key_count,
           index_row.indnatts::integer AS attribute_count,
           ARRAY(
             SELECT pg_catalog.pg_get_indexdef(
               index_row.indexrelid,position,false
             )
             FROM generate_series(1,index_row.indnatts) AS position
             ORDER BY position
           )::text[] AS key_definitions,
           pg_catalog.pg_get_expr(
             index_row.indpred,index_row.indrelid,false
           ) AS predicate,
           coalesce(index_relation.reloptions,ARRAY[]::text[])::text[]
             AS options
    FROM pg_catalog.pg_index AS index_row
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid=index_row.indrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid=index_row.indexrelid
    JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid=index_relation.relam
    LEFT JOIN pg_catalog.pg_constraint AS backing_constraint
      ON backing_constraint.conindid=index_row.indexrelid
    WHERE namespace.oid=CASE
        WHEN ${temporary}::boolean THEN pg_catalog.pg_my_temp_schema()
        ELSE 'public'::regnamespace::oid
      END
      AND relation.relname=ANY(${tableNames}::text[])
      AND index_row.indisunique
      AND NOT index_row.indisprimary
      AND backing_constraint.oid IS NULL
    ORDER BY relation.relname,index_relation.relname
  `;
  return Array.from(rows);
}

async function materializeCanonicalUniqueIndexes(
  transaction: TransactionSql,
  tableNames: readonly string[],
): Promise<CatalogUniqueIndex[]> {
  const dialect = new PgDialect();
  for (const table of canonicalReceiptTables) {
    const config = getTableConfig(table);
    const uniqueIndexes = config.indexes.filter((index) => index.config.unique);
    if (uniqueIndexes.length === 0) {
      continue;
    }
    const columns = config.columns
      .map((column) => `${quoteIdentifier(column.name)} ${column.getSQLType()}`)
      .join(",");
    // eslint-disable-next-line no-await-in-loop -- Each shadow table must exist before its indexes are parsed.
    await transaction.unsafe(
      `CREATE TEMPORARY TABLE ${quoteIdentifier(config.name)} (${columns}) ON COMMIT DROP`,
    );
    for (const index of uniqueIndexes) {
      assert(
        index.config.name,
        `${config.name} has an unnamed canonical unique index`,
      );
      assert.equal(
        index.config.concurrently ?? false,
        false,
        `${config.name}.${index.config.name} cannot be normalized transactionally when concurrent`,
      );
      const keys = index.config.columns
        .map((column) => renderIndexKey(dialect, config.name, column))
        .join(",");
      const predicate =
        index.config.where === undefined
          ? ""
          : ` WHERE ${renderModelSql(
              dialect,
              config.name,
              "index predicate",
              index.config.where,
            )}`;
      const options = renderIndexStorageOptions(config.name, index.config.with);
      const only = index.config.only ? "ONLY " : "";
      // eslint-disable-next-line no-await-in-loop -- PostgreSQL normalizes each canonical index on its preceding shadow table.
      await transaction.unsafe(
        `CREATE UNIQUE INDEX ${quoteIdentifier(index.config.name)} ON ${only}${quoteIdentifier(config.name)} USING ${quoteIdentifier(index.config.method ?? "btree")} (${keys})${options}${predicate}`,
      );
    }
  }
  return readUniqueIndexCatalog(transaction, tableNames, true);
}

async function verifyCanonicalReceiptSchemaParity(): Promise<void> {
  const expectedColumns: CatalogColumn[] = [];
  const expectedConstraints: CatalogConstraint[] = [];
  const expectedForeignKeys: CatalogForeignKey[] = [];

  for (const table of canonicalReceiptTables) {
    const config = getTableConfig(table);
    assert.equal(
      config.schema ?? "public",
      "public",
      `${config.name} left the canonical public schema`,
    );
    expectedColumns.push(
      ...config.columns.map((column, index) => ({
        column_name: column.name,
        not_null: column.notNull,
        ordinal: index + 1,
        sql_type: column.getSQLType(),
        table_name: config.name,
      })),
    );

    const inlinePrimaryColumns = config.columns.filter(
      (column) => column.primary,
    );
    if (inlinePrimaryColumns.length > 0) {
      expectedConstraints.push({
        columns: inlinePrimaryColumns.map((column) => column.name),
        constraint_kind: "p",
        name: `${config.name}_pkey`,
        table_name: config.name,
      });
    }
    expectedConstraints.push(
      ...config.primaryKeys.map((key) => ({
        columns: key.columns.map((column) => column.name),
        constraint_kind: "p" as const,
        name: key.getName(),
        table_name: config.name,
      })),
      ...config.uniqueConstraints.map((key) => {
        const name = key.getName();
        assert(name, `${config.name} has an unnamed unique constraint`);
        return {
          columns: key.columns.map((column) => column.name),
          constraint_kind: "u" as const,
          name,
          table_name: config.name,
        };
      }),
      ...config.columns
        .filter((column) => column.isUnique)
        .map((column) => {
          assert(
            column.uniqueName,
            `${config.name}.${column.name} has an unnamed unique constraint`,
          );
          return {
            columns: [column.name],
            constraint_kind: "u" as const,
            name: column.uniqueName,
            table_name: config.name,
          };
        }),
    );

    expectedForeignKeys.push(
      ...config.foreignKeys.map((key) => {
        const reference = key.reference();
        const foreignConfig = getTableConfig(reference.foreignTable);
        return {
          columns: reference.columns.map((column) => column.name),
          delete_action: key.onDelete ?? "no action",
          foreign_columns: reference.foreignColumns.map(
            (column) => column.name,
          ),
          foreign_schema: foreignConfig.schema ?? "public",
          foreign_table: foreignConfig.name,
          name: key.getName(),
          table_name: config.name,
          update_action: key.onUpdate ?? "no action",
        };
      }),
    );
  }

  const tableNames = canonicalReceiptTables.map(
    (table) => getTableConfig(table).name,
  );
  const liveColumns = await primary<CatalogColumn[]>`
    SELECT relation.relname AS table_name,
           attribute.attname AS column_name,
           attribute.attnum::integer AS ordinal,
           pg_catalog.format_type(
             attribute.atttypid,attribute.atttypmod
           ) AS sql_type,
           attribute.attnotnull AS not_null
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid=relation.oid
    WHERE namespace.nspname='public'
      AND relation.relname=ANY(${tableNames}::text[])
      AND relation.relkind IN ('r','p')
      AND attribute.attnum>0
      AND NOT attribute.attisdropped
    ORDER BY relation.relname,attribute.attnum
  `;
  const liveConstraints = await primary<CatalogConstraint[]>`
    SELECT relation.relname AS table_name,
           constraint_row.conname AS name,
           constraint_row.contype::text AS constraint_kind,
           ARRAY(
             SELECT attribute.attname
             FROM unnest(constraint_row.conkey)
               WITH ORDINALITY AS key(attnum,ordinal)
             JOIN pg_catalog.pg_attribute AS attribute
               ON attribute.attrelid=constraint_row.conrelid
              AND attribute.attnum=key.attnum
             ORDER BY key.ordinal
           )::text[] AS columns
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid=constraint_row.conrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    WHERE namespace.nspname='public'
      AND relation.relname=ANY(${tableNames}::text[])
      AND constraint_row.contype IN ('p','u')
    ORDER BY relation.relname,constraint_row.conname
  `;
  const liveForeignKeys = await primary<CatalogForeignKey[]>`
    SELECT relation.relname AS table_name,
           constraint_row.conname AS name,
           ARRAY(
             SELECT attribute.attname
             FROM unnest(constraint_row.conkey)
               WITH ORDINALITY AS key(attnum,ordinal)
             JOIN pg_catalog.pg_attribute AS attribute
               ON attribute.attrelid=constraint_row.conrelid
              AND attribute.attnum=key.attnum
             ORDER BY key.ordinal
           )::text[] AS columns,
           foreign_namespace.nspname AS foreign_schema,
           foreign_relation.relname AS foreign_table,
           ARRAY(
             SELECT attribute.attname
             FROM unnest(constraint_row.confkey)
               WITH ORDINALITY AS key(attnum,ordinal)
             JOIN pg_catalog.pg_attribute AS attribute
               ON attribute.attrelid=constraint_row.confrelid
              AND attribute.attnum=key.attnum
             ORDER BY key.ordinal
           )::text[] AS foreign_columns,
           CASE constraint_row.confupdtype
             WHEN 'a' THEN 'no action'
             WHEN 'r' THEN 'restrict'
             WHEN 'c' THEN 'cascade'
             WHEN 'n' THEN 'set null'
             WHEN 'd' THEN 'set default'
           END AS update_action,
           CASE constraint_row.confdeltype
             WHEN 'a' THEN 'no action'
             WHEN 'r' THEN 'restrict'
             WHEN 'c' THEN 'cascade'
             WHEN 'n' THEN 'set null'
             WHEN 'd' THEN 'set default'
           END AS delete_action
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid=constraint_row.conrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid=relation.relnamespace
    JOIN pg_catalog.pg_class AS foreign_relation
      ON foreign_relation.oid=constraint_row.confrelid
    JOIN pg_catalog.pg_namespace AS foreign_namespace
      ON foreign_namespace.oid=foreign_relation.relnamespace
    WHERE namespace.nspname='public'
      AND relation.relname=ANY(${tableNames}::text[])
      AND constraint_row.contype='f'
    ORDER BY relation.relname,constraint_row.conname
  `;
  const uniqueIndexParity = await inRolledBackTransaction(
    async (transaction) => ({
      expected: await materializeCanonicalUniqueIndexes(
        transaction,
        tableNames,
      ),
      live: await readUniqueIndexCatalog(transaction, tableNames, false),
    }),
  );

  expectedColumns.sort(
    (left, right) =>
      left.table_name.localeCompare(right.table_name) ||
      left.ordinal - right.ordinal,
  );
  expectedConstraints.sort(byTableAndName);
  expectedForeignKeys.sort(byTableAndName);

  assert.equal(tableNames.length, 6, "receipt parity table set drifted");
  assert.equal(
    expectedForeignKeys.length,
    15,
    "canonical receipt FK coverage drifted",
  );
  assert.deepEqual(
    Array.from(liveColumns),
    expectedColumns,
    "receipt columns diverge from the canonical Drizzle model",
  );
  assert.deepEqual(
    Array.from(liveConstraints),
    expectedConstraints,
    "receipt primary/unique constraints diverge from the canonical Drizzle model",
  );
  assert.deepEqual(
    uniqueIndexParity.live,
    uniqueIndexParity.expected,
    "receipt unique indexes diverge from the canonical Drizzle model",
  );
  assert.deepEqual(
    Array.from(liveForeignKeys),
    expectedForeignKeys,
    "receipt foreign keys diverge from the canonical Drizzle model",
  );
}

async function asApi<T>(
  client: typeof primary,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true),
             set_config('app.service_account_id','',true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate','dfir_retention=runtime',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function asWorker<T>(
  client: typeof primary,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await client.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return { value: await operation(transaction) };
  });
  return result.value;
}

async function setupRootFixture(): Promise<void> {
  const suffix = sequence.toString(36);
  const ticketSuffix = (Number(sequence % 800_000n) + 100_000)
    .toString()
    .padStart(6, "0");
  await primary.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants(id,slug,name)
      VALUES (
        ${fixture.tenant}::uuid,
        ${`dfir-retention-${suffix}`},
        'DFIR mutation retention runtime'
      )
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id)
      VALUES (${fixture.tenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      VALUES (
        ${fixture.user}::uuid,
        ${`dfir-retention-${suffix}@example.invalid`},
        'DFIR retention administrator',
        true
      )
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      ) VALUES (
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
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by,created_by_membership_id,version,updated_at
      )
      SELECT ${fixture.alert}::uuid,${fixture.tenant}::uuid,
             ${`ALT-2099-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key',
             'DFIR retention Alert root',${fixture.user}::uuid,
             ${fixture.membership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.cases(
        id,tenant_id,number,workflow_id,workflow_version,state_key,title,
        created_by_membership_id,created_by_user_id,version,updated_at
      )
      SELECT ${fixture.case}::uuid,${fixture.tenant}::uuid,
             ${`CAS-2099-${ticketSuffix}`},workflow.id,
             workflow.current_version,state.value->>'key',
             'DFIR retention Case root',${fixture.membership}::uuid,
             ${fixture.user}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS workflow_version
        ON workflow_version.tenant_id=workflow.tenant_id
       AND workflow_version.workflow_id=workflow.id
       AND workflow_version.aggregate_kind=workflow.aggregate_kind
       AND workflow_version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
        AS state(value)
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.key='default_case'
        AND (state.value->>'initial')::boolean
    `;
  });
}

async function verifyCatalogBoundary(): Promise<void> {
  const protectedTables = [
    "dfir_mutation_resource_ids",
    "dfir_mutation_replay_keys",
    "dfir_mutation_commands",
    "dfir_mutation_command_results",
    "alert_dfir_resource_commands",
    "alert_dfir_resource_command_results",
    "dfir_ticket_command_retentions",
  ];
  const tableSecurity = await primary<
    { relforcerowsecurity: boolean; relname: string; relrowsecurity: boolean }[]
  >`
    SELECT relname,relrowsecurity,relforcerowsecurity
    FROM pg_catalog.pg_class
    WHERE oid=ANY(${protectedTables}::regclass[])
    ORDER BY relname
  `;
  assert.equal(tableSecurity.length, protectedTables.length);
  for (const relation of tableSecurity) {
    assert.equal(relation.relrowsecurity, true, relation.relname);
    assert.equal(relation.relforcerowsecurity, true, relation.relname);
  }

  const [boundary] = await primary<
    {
      api_execute: boolean;
      owner_name: string;
      public_execute: boolean;
      security_definer: boolean;
      worker_execute: boolean;
    }[]
  >`
    SELECT procedure.prosecdef AS security_definer,
           pg_get_userbyid(procedure.proowner) AS owner_name,
           has_function_privilege(
             'periapsis_worker',procedure.oid,'EXECUTE'
           ) AS worker_execute,
           has_function_privilege(
             'periapsis_api',procedure.oid,'EXECUTE'
           ) AS api_execute,
           has_function_privilege('public',procedure.oid,'EXECUTE')
             AS public_execute
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid=
      'app.prune_expired_dfir_mutation_commands_v1(integer)'::regprocedure
  `;
  assert(boundary);
  assert.equal(boundary.security_definer, true);
  assert.equal(boundary.owner_name, "periapsis_migrator");
  assert.equal(boundary.worker_execute, true);
  assert.equal(boundary.api_execute, false);
  assert.equal(boundary.public_execute, false);

  const [legacyBoundary] = await primary<{ api_execute: boolean }[]>`
    SELECT has_function_privilege(
      'periapsis_api',
      'app.reserve_alert_dfir_resource_command_v1(uuid,uuid,text,uuid,bigint,bytea,bytea)'::regprocedure,
      'EXECUTE'
    ) AS api_execute
  `;
  assert.equal(legacyBoundary?.api_execute, false);

  const [replayPrimaryKey] = await primary<{ definition: string }[]>`
    SELECT pg_get_constraintdef(oid) AS definition
    FROM pg_catalog.pg_constraint
    WHERE conrelid='public.dfir_mutation_replay_keys'::regclass
      AND conname='dfir_mutation_replay_keys_pkey'
  `;
  assert.match(
    replayPrimaryKey?.definition ?? "",
    /PRIMARY KEY \(tenant_id, actor_user_id, operation, key_digest\)/u,
  );
  assert.doesNotMatch(replayPrimaryKey?.definition ?? "", /membership/u);
}

type ReceiptTimes = { createdAt: Date; expiresAt: Date };

async function insertGenericReceipt(
  transaction: TransactionSql,
  input: {
    commandID: string;
    key: string;
    mirrorAlert?: boolean;
    resourceID: string;
    times: ReceiptTimes;
  },
): Promise<void> {
  const keyDigest = digest(`${input.key}:key`);
  await transaction`
    INSERT INTO public.dfir_mutation_resource_ids(
      tenant_id,resource_kind,resource_id,created_at
    ) VALUES (
      ${fixture.tenant}::uuid,'ioc',${input.resourceID}::uuid,
      ${input.times.createdAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.dfir_mutation_replay_keys(
      tenant_id,actor_user_id,actor_membership_id,operation,key_digest,
      first_used_at,receipt_expires_at
    ) VALUES (
      ${fixture.tenant}::uuid,${fixture.user}::uuid,
      ${fixture.membership}::uuid,'dfir.ioc.create',${keyDigest},
      ${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.dfir_mutation_commands(
      command_id,tenant_id,actor_user_id,actor_membership_id,root_kind,
      root_id,operation,resource_kind,resource_id,secondary_resource_id,
      result_version,key_digest,request_digest,created_at,expires_at
    ) VALUES (
      ${input.commandID}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
      ${fixture.membership}::uuid,'alert',${fixture.alert}::uuid,
      'dfir.ioc.create','ioc',${input.resourceID}::uuid,NULL,1,
      ${keyDigest},${digest(`${input.key}:request`)},
      ${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.dfir_mutation_command_results(
      command_id,tenant_id,root_kind,root_id,operation,resource_kind,
      resource_id,result_version,result_snapshot
    ) VALUES (
      ${input.commandID}::uuid,${fixture.tenant}::uuid,'alert',
      ${fixture.alert}::uuid,'dfir.ioc.create','ioc',
      ${input.resourceID}::uuid,1,
      ${transaction.json({
        operation: "dfir.ioc.create",
        projection: { id: input.resourceID },
        resourceId: input.resourceID,
        resourceKind: "ioc",
        resultVersion: 1,
        rootId: fixture.alert,
        rootKind: "alert",
        schemaVersion: 1,
        tenantId: fixture.tenant,
      })}::jsonb
    )
  `;
  if (input.mirrorAlert === true) {
    await transaction`
      INSERT INTO public.alert_dfir_resource_commands(
        command_id,tenant_id,actor_user_id,actor_membership_id,alert_id,
        operation,resource_id,result_version,key_digest,request_digest,
        created_at,expires_at
      ) VALUES (
        ${input.commandID}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,${fixture.membership}::uuid,
        ${fixture.alert}::uuid,'dfir.ioc.create',${input.resourceID}::uuid,1,
        ${keyDigest},${digest(`${input.key}:request`)},
        ${input.times.createdAt}::timestamptz,
        ${input.times.expiresAt}::timestamptz
      )
    `;
  }
}

async function insertAlertReceipt(
  transaction: TransactionSql,
  input: {
    checklistItemID: string;
    commandID: string;
    key: string;
    taskID: string;
    times: ReceiptTimes;
  },
): Promise<void> {
  const keyDigest = digest(`${input.key}:key`);
  await transaction`
    INSERT INTO public.dfir_mutation_resource_ids(
      tenant_id,resource_kind,resource_id,created_at
    ) VALUES
      (${fixture.tenant}::uuid,'task',${input.taskID}::uuid,
       ${input.times.createdAt}::timestamptz),
      (${fixture.tenant}::uuid,'checklist_item',
       ${input.checklistItemID}::uuid,${input.times.createdAt}::timestamptz)
  `;
  await transaction`
    INSERT INTO public.dfir_mutation_replay_keys(
      tenant_id,actor_user_id,actor_membership_id,operation,key_digest,
      first_used_at,receipt_expires_at
    ) VALUES (
      ${fixture.tenant}::uuid,${fixture.user}::uuid,
      ${fixture.membership}::uuid,'dfir.alert.task.create',${keyDigest},
      ${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.alert_dfir_resource_commands(
      command_id,tenant_id,actor_user_id,actor_membership_id,alert_id,
      operation,resource_id,result_version,key_digest,request_digest,
      created_at,expires_at
    ) VALUES (
      ${input.commandID}::uuid,${fixture.tenant}::uuid,${fixture.user}::uuid,
      ${fixture.membership}::uuid,${fixture.alert}::uuid,
      'dfir.alert.task.create',${input.taskID}::uuid,1,${keyDigest},
      ${digest(`${input.key}:request`)},
      ${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.alert_dfir_resource_command_results(
      command_id,tenant_id,alert_id,operation,resource_id,result_version,
      result_snapshot,created_at
    ) VALUES (
      ${input.commandID}::uuid,${fixture.tenant}::uuid,
      ${fixture.alert}::uuid,'dfir.alert.task.create',
      ${input.taskID}::uuid,1,
      ${transaction.json({
        kind: "alert_task",
        task: {
          alertId: fixture.alert,
          checklist: [
            {
              completed: false,
              id: input.checklistItemID,
              title: "Retain evidence",
            },
          ],
          id: input.taskID,
          tenantId: fixture.tenant,
          version: 1,
        },
      })}::jsonb,
      ${input.times.createdAt}::timestamptz
    )
  `;
}

async function insertCaseReceipt(
  transaction: TransactionSql,
  input: {
    checklistItemID: string;
    commandID: string;
    key: string;
    taskID: string;
    times: ReceiptTimes;
  },
): Promise<void> {
  const keyDigest = digest(`${input.key}:key`);
  await transaction`
    INSERT INTO public.dfir_mutation_resource_ids(
      tenant_id,resource_kind,resource_id,created_at
    ) VALUES
      (${fixture.tenant}::uuid,'task',${input.taskID}::uuid,
       ${input.times.createdAt}::timestamptz),
      (${fixture.tenant}::uuid,'checklist_item',
       ${input.checklistItemID}::uuid,${input.times.createdAt}::timestamptz)
  `;
  await transaction`
    INSERT INTO public.dfir_mutation_replay_keys(
      tenant_id,actor_user_id,actor_membership_id,operation,key_digest,
      first_used_at,receipt_expires_at
    ) VALUES (
      ${fixture.tenant}::uuid,${fixture.user}::uuid,
      ${fixture.membership}::uuid,'case.dfir.task.create',${keyDigest},
      ${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.ticket_commands(
      id,tenant_id,operation,actor_membership_id,actor_user_id,
      key_digest,request_digest,result_alert_id,result_case_id,
      result_version,result_metadata,created_at
    ) VALUES (
      ${input.commandID}::uuid,${fixture.tenant}::uuid,
      'case.dfir.task.create',${fixture.membership}::uuid,
      ${fixture.user}::uuid,${keyDigest},${digest(`${input.key}:request`)},
      NULL,${fixture.case}::uuid,1,
      ${transaction.json({
        task: {
          caseId: fixture.case,
          checklist: [
            {
              completed: false,
              id: input.checklistItemID,
              title: "Retain evidence",
            },
          ],
          id: input.taskID,
          version: 1,
        },
      })}::jsonb,
      ${input.times.createdAt}::timestamptz
    )
  `;
  await transaction`
    INSERT INTO public.dfir_ticket_command_retentions(
      tenant_id,command_id,operation,command_created_at,expires_at
    ) VALUES (
      ${fixture.tenant}::uuid,${input.commandID}::uuid,
      'case.dfir.task.create',${input.times.createdAt}::timestamptz,
      ${input.times.expiresAt}::timestamptz
    )
  `;
}

async function seedHistoryAndReceipts(): Promise<void> {
  const lockedTimes = {
    createdAt: new Date(now - 72 * hour),
    expiresAt: new Date(now - 48 * hour),
  };
  const expiredTimes = {
    createdAt: new Date(now - 48 * hour),
    expiresAt: new Date(now - 24 * hour),
  };
  const activeTimes = {
    createdAt: new Date(now),
    expiresAt: new Date(now + 24 * hour),
  };
  const maximumTimes = {
    createdAt: new Date(now + hour),
    expiresAt: new Date(now + hour + 7 * 24 * hour),
  };

  await primary.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    await insertGenericReceipt(transaction, {
      commandID: fixture.genericLockedCommand,
      key: "generic-locked",
      resourceID: fixture.genericLockedResource,
      times: lockedTimes,
    });
    await insertGenericReceipt(transaction, {
      commandID: fixture.genericOtherCommand,
      key: "generic-other",
      mirrorAlert: true,
      resourceID: fixture.genericOtherResource,
      times: expiredTimes,
    });
    await insertGenericReceipt(transaction, {
      commandID: fixture.genericActiveCommand,
      key: "generic-active",
      resourceID: fixture.genericActiveResource,
      times: activeTimes,
    });
    await insertGenericReceipt(transaction, {
      commandID: fixture.genericMaximumCommand,
      key: "generic-maximum",
      resourceID: fixture.genericMaximumResource,
      times: maximumTimes,
    });
    await insertAlertReceipt(transaction, {
      checklistItemID: fixture.alertExpiredChecklistItem,
      commandID: fixture.alertExpiredCommand,
      key: "alert-expired",
      taskID: fixture.alertExpiredTask,
      times: expiredTimes,
    });
    await insertAlertReceipt(transaction, {
      checklistItemID: fixture.alertActiveChecklistItem,
      commandID: fixture.alertActiveCommand,
      key: "alert-active",
      taskID: fixture.alertActiveTask,
      times: activeTimes,
    });
    await insertAlertReceipt(transaction, {
      checklistItemID: fixture.alertMaximumChecklistItem,
      commandID: fixture.alertMaximumCommand,
      key: "alert-maximum",
      taskID: fixture.alertMaximumTask,
      times: maximumTimes,
    });
    await insertCaseReceipt(transaction, {
      checklistItemID: fixture.caseExpiredChecklistItem,
      commandID: fixture.caseExpiredCommand,
      key: "case-expired",
      taskID: fixture.caseExpiredTask,
      times: expiredTimes,
    });
    await insertCaseReceipt(transaction, {
      checklistItemID: fixture.caseActiveChecklistItem,
      commandID: fixture.caseActiveCommand,
      key: "case-active",
      taskID: fixture.caseActiveTask,
      times: activeTimes,
    });
    await insertCaseReceipt(transaction, {
      checklistItemID: fixture.caseMaximumChecklistItem,
      commandID: fixture.caseMaximumCommand,
      key: "case-maximum",
      taskID: fixture.caseMaximumTask,
      times: maximumTimes,
    });
    await transaction`
      INSERT INTO public.ticket_commands(
        id,tenant_id,operation,actor_membership_id,actor_user_id,
        key_digest,request_digest,result_case_id,result_version,
        result_metadata,created_at
      ) VALUES (
        ${fixture.nonDfirTicketCommand}::uuid,${fixture.tenant}::uuid,
        'case.update',${fixture.membership}::uuid,${fixture.user}::uuid,
        ${digest("non-dfir:key")},${digest("non-dfir:request")},
        ${fixture.case}::uuid,1,'{}'::jsonb,
        ${expiredTimes.createdAt}::timestamptz
      )
    `;

    await transaction`
      INSERT INTO public.audit_events(
        id,tenant_id,sequence,actor_type,action,resource_type,resource_id,
        outcome,reason,metadata
      ) VALUES (
        ${fixture.audit}::uuid,${fixture.tenant}::uuid,0,'system',
        'dfir.retention.fixture','dfir_receipt',
        ${fixture.genericLockedCommand}::uuid,'success',
        'retention history survival proof','{}'::jsonb
      )
    `;
    await transaction`
      INSERT INTO public.dfir_activities(
        id,tenant_id,alert_id,case_id,resource_kind,resource_id,action,
        summary,actor_principal_kind,details
      ) VALUES (
        ${fixture.activity}::uuid,${fixture.tenant}::uuid,
        ${fixture.alert}::uuid,NULL,'task',${fixture.alertExpiredTask}::uuid,
        'dfir.retention.fixture','Retention history survival proof',
        'system','{}'::jsonb
      )
    `;
    await transaction`
      INSERT INTO public.outbox_events(
        id,tenant_id,aggregate_type,aggregate_id,event_type,payload
      ) VALUES (
        ${fixture.outbox}::uuid,${fixture.tenant}::uuid,'dfir_receipt',
        ${fixture.genericLockedCommand}::uuid,'dfir.retention.fixture',
        '{}'::jsonb
      )
    `;
  });
}

async function verifyExpiryBoundsRejectInvalidRows(): Promise<void> {
  const tooShort = {
    createdAt: new Date(now + 2 * hour),
    expiresAt: new Date(now + 2 * hour + 24 * hour - 1),
  };
  const tooLong = {
    createdAt: new Date(now + 3 * hour),
    expiresAt: new Date(now + 3 * hour + 7 * 24 * hour + 1),
  };
  await expectSqlState(
    primary.begin((transaction) =>
      insertGenericReceipt(transaction, {
        commandID: uuid(1001),
        key: "generic-too-short",
        resourceID: uuid(1002),
        times: tooShort,
      }),
    ),
    "23514",
    "generic receipt accepted a retention shorter than 24 hours",
  );
  await expectSqlState(
    primary.begin((transaction) =>
      insertAlertReceipt(transaction, {
        checklistItemID: uuid(1011),
        commandID: uuid(1012),
        key: "alert-too-long",
        taskID: uuid(1013),
        times: tooLong,
      }),
    ),
    "23514",
    "Alert receipt accepted a retention longer than 7 days",
  );
  await expectSqlState(
    primary.begin((transaction) =>
      insertCaseReceipt(transaction, {
        checklistItemID: uuid(1021),
        commandID: uuid(1022),
        key: "case-too-short",
        taskID: uuid(1023),
        times: tooShort,
      }),
    ),
    "23514",
    "Case task receipt accepted a retention shorter than 24 hours",
  );
}

async function verifyExpiredReplayFailsClosed(): Promise<void> {
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_dfir_mutation_command_v1(
        ${uuid(1101)}::uuid,'alert',${fixture.alert}::uuid,
        'dfir.ioc.create','ioc',${fixture.genericOtherResource}::uuid,NULL,
        1,${digest("generic-other:key")},${digest("generic-other:request")}
      )
    `,
    ),
    "23505",
    "generic expired replay did not fail closed before cleanup",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_alert_investigation_command_v1(
        ${uuid(1102)}::uuid,${fixture.alert}::uuid,
        'dfir.alert.task.create',${fixture.alertExpiredTask}::uuid,1,
        ${digest("alert-expired:key")},${digest("alert-expired:request")}
      )
    `,
    ),
    "23505",
    "Alert expired replay did not fail closed before cleanup",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_case_dfir_command_v1(
        ${uuid(1103)}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${fixture.caseExpiredTask}::uuid,1,
        ${digest("case-expired:key")},${digest("case-expired:request")},
        NULL::jsonb
      )
    `,
    ),
    "23505",
    "Case task expired replay did not fail closed before cleanup",
  );
}

async function verifyRoleIsolation(): Promise<void> {
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.prune_expired_dfir_mutation_commands_v1(1)
    `,
    ),
    "42501",
    "API role executed the worker-only prune ABI",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      DELETE FROM public.dfir_mutation_commands
      WHERE command_id=${fixture.genericOtherCommand}::uuid
    `,
    ),
    "42501",
    "API role directly deleted a protected receipt",
  );
  await Promise.all(
    ([null, 0, 1001] as const).map((batch) =>
      expectSqlState(
        asWorker(
          primary,
          (transaction) => transaction`
          SELECT *
          FROM app.prune_expired_dfir_mutation_commands_v1(${batch})
        `,
        ),
        "22023",
        `worker cleanup accepted out-of-contract batch ${batch}`,
      ),
    ),
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_case_dfir_command_v1(
        ${uuid(1251)}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${uuid(1252)}::uuid,NULL::bigint,
        ${digest("case-null-version:key")},
        ${digest("case-null-version:request")},NULL::jsonb
      )
    `,
    ),
    "22023",
    "Case receipt reservation accepted a NULL result version",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_alert_investigation_command_v1(
        ${uuid(1253)}::uuid,${fixture.alert}::uuid,
        'dfir.alert.task.create',${uuid(1254)}::uuid,NULL::bigint,
        ${digest("alert-null-version:key")},
        ${digest("alert-null-version:request")}
      )
    `,
    ),
    "22023",
    "Alert receipt reservation accepted a NULL result version",
  );
}

async function verifyBoundedConcurrentCleanup(): Promise<void> {
  await primary.begin(async (transaction) => {
    await transaction`
      SELECT command_id
      FROM public.dfir_mutation_commands
      WHERE command_id=${fixture.genericLockedCommand}::uuid
      FOR UPDATE
    `;
    const [counts] = await asWorker(
      contender,
      (worker) =>
        worker<CleanupCounts[]>`
        SELECT results_deleted::text,commands_deleted::text
        FROM app.prune_expired_dfir_mutation_commands_v1(1)
      `,
    );
    assert.deepEqual(counts, {
      commands_deleted: "4",
      results_deleted: "2",
    });
    const [visibility] = await transaction<
      { locked_count: string; mirror_count: string; other_count: string }[]
    >`
      SELECT
        count(*) FILTER (
          WHERE command_id=${fixture.genericLockedCommand}::uuid
        )::text AS locked_count,
        count(*) FILTER (
          WHERE command_id=${fixture.genericOtherCommand}::uuid
        )::text AS other_count,
        (SELECT count(*)::text
         FROM public.alert_dfir_resource_commands
         WHERE command_id=${fixture.genericOtherCommand}::uuid)
          AS mirror_count
      FROM public.dfir_mutation_commands
    `;
    assert.deepEqual(visibility, {
      locked_count: "1",
      mirror_count: "0",
      other_count: "0",
    });
  });

  const [secondPass] = await asWorker(
    primary,
    (transaction) =>
      transaction<CleanupCounts[]>`
      SELECT results_deleted::text,commands_deleted::text
      FROM app.prune_expired_dfir_mutation_commands_v1(1)
    `,
  );
  assert.deepEqual(secondPass, {
    commands_deleted: "1",
    results_deleted: "1",
  });
  const [emptyPass] = await asWorker(
    primary,
    (transaction) =>
      transaction<CleanupCounts[]>`
      SELECT results_deleted::text,commands_deleted::text
      FROM app.prune_expired_dfir_mutation_commands_v1(1)
    `,
  );
  assert.deepEqual(emptyPass, {
    commands_deleted: "0",
    results_deleted: "0",
  });

  const [survivors] = await primary<
    {
      active_alert: string;
      active_case: string;
      active_generic: string;
      history_activity: string;
      history_audit: string;
      history_outbox: string;
      non_dfir_ticket: string;
      tombstones: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::text FROM public.dfir_mutation_commands
       WHERE command_id IN (
         ${fixture.genericActiveCommand}::uuid,
         ${fixture.genericMaximumCommand}::uuid
       )) AS active_generic,
      (SELECT count(*)::text FROM public.alert_dfir_resource_commands
       WHERE command_id IN (
         ${fixture.alertActiveCommand}::uuid,
         ${fixture.alertMaximumCommand}::uuid
       )) AS active_alert,
      (SELECT count(*)::text FROM public.ticket_commands
       WHERE id IN (
         ${fixture.caseActiveCommand}::uuid,
         ${fixture.caseMaximumCommand}::uuid
       )) AS active_case,
      (SELECT count(*)::text FROM public.ticket_commands
       WHERE id=${fixture.nonDfirTicketCommand}::uuid) AS non_dfir_ticket,
      (SELECT count(*)::text FROM public.dfir_mutation_replay_keys
       WHERE tenant_id=${fixture.tenant}::uuid
         AND key_digest IN (
           ${digest("generic-locked:key")},
           ${digest("generic-other:key")},
           ${digest("alert-expired:key")},
           ${digest("case-expired:key")}
         )) AS tombstones,
      (SELECT count(*)::text FROM public.audit_events
       WHERE id=${fixture.audit}::uuid) AS history_audit,
      (SELECT count(*)::text FROM public.dfir_activities
       WHERE id=${fixture.activity}::uuid) AS history_activity,
      (SELECT count(*)::text FROM public.outbox_events
       WHERE id=${fixture.outbox}::uuid) AS history_outbox
  `;
  assert.deepEqual(survivors, {
    active_alert: "2",
    active_case: "2",
    active_generic: "2",
    history_activity: "1",
    history_audit: "1",
    history_outbox: "1",
    non_dfir_ticket: "1",
    tombstones: "4",
  });
}

async function verifyReplayAndResourceTombstonesAfterCleanup(): Promise<void> {
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_dfir_mutation_command_v1(
        ${uuid(1201)}::uuid,'alert',${fixture.alert}::uuid,
        'dfir.ioc.create','ioc',${fixture.genericOtherResource}::uuid,NULL,
        1,${digest("generic-other:key")},${digest("generic-other:request")}
      )
    `,
    ),
    "23505",
    "expired generic idempotency key became reusable after cleanup",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_dfir_mutation_command_v1(
        ${uuid(1202)}::uuid,'alert',${fixture.alert}::uuid,
        'dfir.ioc.create','ioc',${fixture.genericOtherResource}::uuid,NULL,
        1,${digest("generic-resource-reuse:key")},
        ${digest("generic-resource-reuse:request")}
      )
    `,
    ),
    "23505",
    "generic caller-owned identifier became reusable with a new key",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_alert_investigation_command_v1(
        ${uuid(1203)}::uuid,${fixture.alert}::uuid,
        'dfir.alert.task.create',${fixture.alertExpiredTask}::uuid,1,
        ${digest("alert-expired:key")},${digest("alert-expired:request")}
      )
    `,
    ),
    "23505",
    "expired Alert idempotency key became reusable after cleanup",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_case_dfir_command_v1(
        ${uuid(1204)}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${fixture.caseExpiredTask}::uuid,1,
        ${digest("case-expired:key")},${digest("case-expired:request")},
        NULL::jsonb
      )
    `,
    ),
    "23505",
    "expired Case task idempotency key became reusable after cleanup",
  );
  await expectSqlState(
    primary`
      DELETE FROM public.dfir_mutation_resource_ids
      WHERE tenant_id=${fixture.tenant}::uuid
        AND resource_kind='ioc'
        AND resource_id=${fixture.genericOtherResource}::uuid
    `,
    "55000",
    "durable resource tombstone was deletable",
  );
}

async function verifySharedLinkEventRetention(): Promise<void> {
  const createdAt = new Date(now - 48 * hour);
  const expiresAt = new Date(now - 24 * hour);
  const keyDigest = digest("shared-link-expired:key");
  await primary.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    await transaction`
      INSERT INTO public.dfir_iocs(
        id,tenant_id,type,value,normalized_value,description,source,
        confidence,tlp,first_seen,last_seen,malicious_state,
        created_by_membership_id,updated_by_membership_id,version
      ) VALUES (
        ${fixture.sharedIoc}::uuid,${fixture.tenant}::uuid,'domain',
        'retention.example.invalid','retention.example.invalid',
        'Shared-link tombstone proof','retention-runtime',50,'green',
        transaction_timestamp(),transaction_timestamp(),'unknown',
        ${fixture.membership}::uuid,${fixture.membership}::uuid,1
      )
    `;
    await transaction`
      INSERT INTO public.dfir_mutation_resource_ids(
        tenant_id,resource_kind,resource_id,created_at
      ) VALUES (
        ${fixture.tenant}::uuid,'shared_link_event',
        ${fixture.sharedLinkEvent}::uuid,${createdAt}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.dfir_mutation_replay_keys(
        tenant_id,actor_user_id,actor_membership_id,operation,key_digest,
        first_used_at,receipt_expires_at
      ) VALUES (
        ${fixture.tenant}::uuid,${fixture.user}::uuid,
        ${fixture.membership}::uuid,'dfir.ioc.link',${keyDigest},
        ${createdAt}::timestamptz,${expiresAt}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.dfir_mutation_commands(
        command_id,tenant_id,actor_user_id,actor_membership_id,root_kind,
        root_id,operation,resource_kind,resource_id,secondary_resource_id,
        result_version,key_digest,request_digest,created_at,expires_at
      ) VALUES (
        ${fixture.sharedLinkCommand}::uuid,${fixture.tenant}::uuid,
        ${fixture.user}::uuid,${fixture.membership}::uuid,'case',
        ${fixture.case}::uuid,'dfir.ioc.link','ioc',
        ${fixture.sharedIoc}::uuid,${fixture.sharedLinkEvent}::uuid,2,
        ${keyDigest},${digest("shared-link-expired:request")},
        ${createdAt}::timestamptz,${expiresAt}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.dfir_shared_resource_link_events(
        id,tenant_id,resource_kind,ioc_id,asset_id,case_id,alert_id,link_id,
        event_kind,prior_version,result_version,actor_membership_id,occurred_at
      ) VALUES (
        ${fixture.sharedLinkEvent}::uuid,${fixture.tenant}::uuid,'ioc',
        ${fixture.sharedIoc}::uuid,NULL,${fixture.case}::uuid,NULL,
        ${fixture.sharedLinkEvent}::uuid,'linked',1,2,
        ${fixture.membership}::uuid,${createdAt}::timestamptz
      )
    `;
    await transaction`
      INSERT INTO public.dfir_mutation_command_results(
        command_id,tenant_id,root_kind,root_id,operation,resource_kind,
        resource_id,result_version,result_snapshot
      ) VALUES (
        ${fixture.sharedLinkCommand}::uuid,${fixture.tenant}::uuid,'case',
        ${fixture.case}::uuid,'dfir.ioc.link','ioc',
        ${fixture.sharedIoc}::uuid,2,
        ${transaction.json({
          operation: "dfir.ioc.link",
          resourceId: fixture.sharedIoc,
          resourceKind: "ioc",
          resultVersion: 2,
          rootId: fixture.case,
          rootKind: "case",
          schemaVersion: 1,
          secondaryResourceId: fixture.sharedLinkEvent,
          tenantId: fixture.tenant,
          projection: {
            confidence: 50,
            description: "Shared-link tombstone proof",
            firstSeen: "2026-09-04T10:00:00Z",
            id: fixture.sharedIoc,
            lastSeen: "2026-09-04T10:00:00Z",
            malicious: "unknown",
            normalizedValue: "retention.example.invalid",
            source: "retention-runtime",
            tags: [],
            tenantId: fixture.tenant,
            tlp: "green",
            type: "domain",
            value: "retention.example.invalid",
          },
        })}::jsonb
      )
    `;
  });

  const [counts] = await asWorker(
    primary,
    (transaction) =>
      transaction<CleanupCounts[]>`
      SELECT results_deleted::text,commands_deleted::text
      FROM app.prune_expired_dfir_mutation_commands_v1(1)
    `,
  );
  assert.deepEqual(counts, {
    commands_deleted: "1",
    results_deleted: "1",
  });
  const [registry] = await primary<
    {
      command_count: string;
      event_history: string;
      event_tombstone: string;
    }[]
  >`
    SELECT
      (SELECT count(*)::text
       FROM public.dfir_mutation_commands
       WHERE command_id=${fixture.sharedLinkCommand}::uuid) AS command_count,
      (SELECT count(*)::text
       FROM public.dfir_shared_resource_link_events
       WHERE tenant_id=${fixture.tenant}::uuid
         AND id=${fixture.sharedLinkEvent}::uuid) AS event_history,
      (SELECT count(*)::text
       FROM public.dfir_mutation_resource_ids
       WHERE tenant_id=${fixture.tenant}::uuid
         AND resource_kind='shared_link_event'
         AND resource_id=${fixture.sharedLinkEvent}::uuid) AS event_tombstone
  `;
  assert.deepEqual(registry, {
    command_count: "0",
    event_history: "1",
    event_tombstone: "1",
  });
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_dfir_mutation_command_v1(
        ${uuid(1010)}::uuid,'case',${fixture.case}::uuid,
        'dfir.ioc.link','ioc',${fixture.sharedIoc}::uuid,
        ${fixture.sharedLinkEvent}::uuid,2,
        ${digest("shared-link-reuse:key")},
        ${digest("shared-link-reuse:request")}
      )
    `,
    ),
    "23505",
    "shared link-event identifier became reusable after receipt cleanup",
  );
}

async function verifyCaseReceiptReservesIdentifiers(): Promise<void> {
  const snapshot = (taskID: string, checklistID: string) => ({
    kind: "case_task",
    task: {
      caseId: fixture.case,
      checklist: [
        {
          completed: false,
          id: checklistID,
          title: "Preserve receipt identifier",
        },
      ],
      commentIds: [],
      createdAt: "2026-09-04T10:00:00Z",
      description: "Receipt-only durable identifier proof",
      id: taskID,
      priority: "medium",
      status: "todo",
      tenantId: fixture.tenant,
      title: "Retention reservation",
      updatedAt: "2026-09-04T10:00:00Z",
      version: 1,
    },
  });

  const [reservation] = await asApi(
    primary,
    (transaction) =>
      transaction<{ replayed: boolean }[]>`
      SELECT replayed
      FROM app.reserve_case_dfir_command_v1(
        ${fixture.reservedCaseCommand}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${fixture.reservedCaseTask}::uuid,1,
        ${digest("case-reserved-identifiers:key")},
        ${digest("case-reserved-identifiers:request")},
        ${transaction.json(
          snapshot(fixture.reservedCaseTask, fixture.reservedCaseChecklist),
        )}::jsonb
      )
    `,
  );
  assert.equal(reservation?.replayed, false);

  const [registry] = await primary<{ checklist_item: string; task: string }[]>`
    SELECT
      count(*) FILTER (
        WHERE resource_kind='task'
          AND resource_id=${fixture.reservedCaseTask}::uuid
      )::text AS task,
      count(*) FILTER (
        WHERE resource_kind='checklist_item'
          AND resource_id=${fixture.reservedCaseChecklist}::uuid
      )::text AS checklist_item
    FROM public.dfir_mutation_resource_ids
    WHERE tenant_id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(registry, { checklist_item: "1", task: "1" });

  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_case_dfir_command_v1(
        ${uuid(1311)}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${fixture.reservedCaseTask}::uuid,1,
        ${digest("case-reserved-task-reuse:key")},
        ${digest("case-reserved-task-reuse:request")},
        ${transaction.json(
          snapshot(fixture.reservedCaseTask, uuid(1312)),
        )}::jsonb
      )
    `,
    ),
    "23505",
    "a task identifier bound only by a receipt was reusable",
  );
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      SELECT * FROM app.reserve_case_dfir_command_v1(
        ${uuid(1313)}::uuid,${fixture.case}::uuid,
        'case.dfir.task.create',${uuid(1314)}::uuid,1,
        ${digest("case-reserved-checklist-reuse:key")},
        ${digest("case-reserved-checklist-reuse:request")},
        ${transaction.json(
          snapshot(uuid(1314), fixture.reservedCaseChecklist),
        )}::jsonb
      )
    `,
    ),
    "23505",
    "a checklist identifier bound only by a receipt was reusable",
  );
}

async function verifyTaskAndRetractionResourceGuards(): Promise<void> {
  await asApi(primary, async (transaction) => {
    await transaction`
      INSERT INTO public.dfir_tasks(
        id,tenant_id,case_id,title,description,status,priority,checklist,
        comment_ids,created_by_membership_id,updated_by_membership_id,
        version,created_at,updated_at
      ) VALUES (
        ${fixture.checklistTask}::uuid,${fixture.tenant}::uuid,
        ${fixture.case}::uuid,'Retention checklist task',
        'Durable checklist identifier proof','todo','medium',
        ${transaction.json([
          {
            completed: false,
            id: fixture.checklistItem,
            title: "Acquire evidence",
          },
        ])}::jsonb,ARRAY[]::uuid[],${fixture.membership}::uuid,
        ${fixture.membership}::uuid,1,transaction_timestamp(),
        transaction_timestamp()
      )
    `;
    await transaction`
      UPDATE public.dfir_tasks
      SET checklist=${transaction.json([
        {
          completed: true,
          id: fixture.checklistItem,
          title: "Acquire and seal evidence",
        },
      ])}::jsonb,
          version=2,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.checklistTask}::uuid
    `;
    await transaction`
      UPDATE public.dfir_tasks
      SET checklist='[]'::jsonb,version=3,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.checklistTask}::uuid
    `;
  });
  await expectSqlState(
    asApi(
      primary,
      (transaction) => transaction`
      UPDATE public.dfir_tasks
      SET checklist=${transaction.json([
        {
          completed: false,
          id: fixture.checklistItem,
          title: "Re-added evidence item",
        },
      ])}::jsonb,
          version=4,updated_at=transaction_timestamp()
      WHERE tenant_id=${fixture.tenant}::uuid
        AND id=${fixture.checklistTask}::uuid
    `,
    ),
    "23505",
    "removed checklist identifier was reusable",
  );

  await primary.begin(async (transaction) => {
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.user},true)
    `;
    await transaction`
      INSERT INTO public.dfir_relationships(
        id,tenant_id,case_id,source_kind,source_id,target_kind,
        target_external_type,target_external_id,relationship_type,
        created_by_membership_id,version
      ) VALUES (
        ${fixture.relationship}::uuid,${fixture.tenant}::uuid,
        ${fixture.case}::uuid,'case',${fixture.case}::uuid,'external',
        'url','https://example.invalid/retention-proof','references',
        ${fixture.membership}::uuid,1
      )
    `;
    await transaction`
      INSERT INTO public.dfir_mutation_resource_ids(
        tenant_id,resource_kind,resource_id
      ) VALUES (
        ${fixture.tenant}::uuid,'relationship_retraction',
        ${fixture.retraction}::uuid
      )
    `;
  });
  await expectSqlState(
    primary`
      INSERT INTO public.dfir_relationship_retractions(
        id,tenant_id,relationship_id,alert_id,case_id,
        retracted_by_membership_id,reason,prior_version,result_version,
        retracted_at
      ) VALUES (
        ${fixture.retraction}::uuid,${fixture.tenant}::uuid,
        ${fixture.relationship}::uuid,NULL,${fixture.case}::uuid,
        ${fixture.membership}::uuid,'duplicate retraction identifier',1,2,
        transaction_timestamp()
      )
    `,
    "23505",
    "relationship retraction identifier was reusable",
  );

  const [registry] = await primary<
    { checklist_item: string; relationship_retraction: string; task: string }[]
  >`
    SELECT
      count(*) FILTER (
        WHERE resource_kind='task'
          AND resource_id=${fixture.checklistTask}::uuid
      )::text AS task,
      count(*) FILTER (
        WHERE resource_kind='checklist_item'
          AND resource_id=${fixture.checklistItem}::uuid
      )::text AS checklist_item,
      count(*) FILTER (
        WHERE resource_kind='relationship_retraction'
          AND resource_id=${fixture.retraction}::uuid
      )::text AS relationship_retraction
    FROM public.dfir_mutation_resource_ids
    WHERE tenant_id=${fixture.tenant}::uuid
  `;
  assert.deepEqual(registry, {
    checklist_item: "1",
    relationship_retraction: "1",
    task: "1",
  });
}

try {
  await verifyCanonicalReceiptSchemaParity();
  await setupRootFixture();
  await verifyCatalogBoundary();
  await seedHistoryAndReceipts();
  await verifyExpiryBoundsRejectInvalidRows();
  await verifyExpiredReplayFailsClosed();
  await verifyRoleIsolation();
  await verifyBoundedConcurrentCleanup();
  await verifyReplayAndResourceTombstonesAfterCleanup();
  await verifySharedLinkEventRetention();
  await verifyCaseReceiptReservesIdentifiers();
  await verifyTaskAndRetractionResourceGuards();
} finally {
  await Promise.all([
    primary.end({ timeout: 1 }),
    contender.end({ timeout: 1 }),
  ]);
}
