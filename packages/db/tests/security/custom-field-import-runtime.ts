import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonObject = { [key: string]: postgres.JSONValue };

const databaseUrl =
  process.env.PERIAPSIS_CUSTOM_FIELD_IMPORT_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_CUSTOM_FIELD_IMPORT_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const fixture = {
  tenant: "01a0b225-0000-7000-8000-000000000001",
  foreignTenant: "01a0b225-0000-7000-8000-000000000002",
  user: "01a0b225-0000-7000-8000-000000000101",
  foreignUser: "01a0b225-0000-7000-8000-000000000102",
  membership: "01a0b225-0000-7000-8000-000000000201",
  foreignMembership: "01a0b225-0000-7000-8000-000000000202",
  session: "01a0b225-0000-7000-8000-000000000301",
  foreignSession: "01a0b225-0000-7000-8000-000000000302",
  sessionFamily: "01a0b225-0000-7000-8000-000000000303",
  foreignSessionFamily: "01a0b225-0000-7000-8000-000000000304",
  definition: "01a0b225-0000-7000-8000-000000000401",
  definitionRevision: "01a0b225-0000-7000-8000-000000000402",
  alertZero: "01a0b225-0000-7000-8000-000000000501",
  alertMissing: "01a0b225-0000-7000-8000-000000000502",
  alertNull: "01a0b225-0000-7000-8000-000000000503",
  alertEmpty: "01a0b225-0000-7000-8000-000000000504",
  importJob: "01a0b225-0000-7000-8000-000000000601",
  foreignJob: "01a0b225-0000-7000-8000-000000000602",
  cancelJob: "01a0b225-0000-7000-8000-000000000603",
  activeCancelJob: "01a0b225-0000-7000-8000-000000000604",
  request: "01a0b225-0000-7000-8000-000000000701",
  correlation: "01a0b225-0000-7000-8000-000000000702",
  cancelRequest: "01a0b225-0000-7000-8000-000000000703",
  cancelCorrelation: "01a0b225-0000-7000-8000-000000000704",
  worker: "01a0b225-0000-7000-8000-000000000801",
  otherWorker: "01a0b225-0000-7000-8000-000000000802",
  fallbackServicePrincipal: "01a0b225-0000-7000-8000-000000000803",
} as const;

const tables = [
  "custom_field_import_jobs",
  "custom_field_import_rows",
  "custom_field_import_results",
  "custom_field_import_command_receipts",
] as const;

function digest(label: string): string {
  return createHash("sha256")
    .update(`custom-field-import-security:${label}`)
    .digest("hex");
}

function isJsonObject(
  value: postgres.JSONValue | undefined,
): value is JsonObject {
  return (
    value !== null &&
    value !== undefined &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

function asObject(
  value: postgres.JSONValue | undefined,
  message: string,
): JsonObject {
  assert(isJsonObject(value), message);
  return value;
}

function asArray(
  value: postgres.JSONValue | undefined,
  message: string,
): postgres.JSONValue[] {
  assert(Array.isArray(value), message);
  return value;
}

function asString(
  value: postgres.JSONValue | undefined,
  message: string,
): string {
  if (typeof value !== "string") {
    throw new TypeError(message);
  }
  return value;
}

function asNumber(
  value: postgres.JSONValue | undefined,
  message: string,
): number {
  if (typeof value !== "number") {
    throw new TypeError(message);
  }
  return value;
}

function requiredJson(
  value: postgres.JSONValue | undefined,
  message: string,
): postgres.JSONValue {
  if (value === undefined) {
    throw new TypeError(message);
  }
  return value;
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

type RuntimeRole =
  | "periapsis_api"
  | "periapsis_worker"
  | "periapsis_notifier"
  | "periapsis_auditor"
  | "periapsis_custom_field_import_owner";

async function asRole<T>(
  transaction: TransactionSql,
  role: RuntimeRole,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await transaction.savepoint(async (sql) => {
    await sql.unsafe(`SET LOCAL ROLE "${role}"`);
    const value = await operation(sql);
    await sql.unsafe("RESET ROLE");
    return { value };
  });
  return result.value;
}

async function asTenantRole<T>(
  transaction: TransactionSql,
  role: RuntimeRole,
  tenantId: string,
  userId: string,
  operation: (sql: TransactionSql) => Promise<T>,
): Promise<T> {
  return asRole(transaction, role, async (sql) => {
    await sql`
      SELECT set_config('app.tenant_id', ${tenantId}, true),
             set_config('app.user_id', ${userId}, true),
             set_config('app.service_account_id', '', true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate', 'custom-field-import=security', true)
    `;
    return operation(sql);
  });
}

async function callFunction(
  sql: TransactionSql,
  functionName:
    | "commit_custom_field_import_request_v1"
    | "lookup_custom_field_import_replay_v1"
    | "get_custom_field_import_v1"
    | "list_custom_field_import_results_v1"
    | "commit_custom_field_import_cancellation_v1"
    | "list_custom_field_import_queues_v1"
    | "load_custom_field_import_worker_v1"
    | "commit_custom_field_import_transition_v1"
    | "load_custom_field_import_row_v1"
    | "commit_custom_field_import_row_v1",
  request: JsonObject,
): Promise<JsonObject> {
  const [row] = await sql<{ response: JsonObject }[]>`
    SELECT ${sql(`app.${functionName}`)}(${sql.json(request)}::jsonb) AS response
  `;
  return asObject(row?.response, `${functionName} returned no JSON object`);
}

function instant(value: Date): string {
  return value.toISOString().replace(/(\.\d{3})Z$/u, "$1000Z");
}

function addMilliseconds(value: string, milliseconds: number): string {
  return instant(new Date(new Date(value).getTime() + milliseconds));
}

function manifestDigest(manifest: JsonObject): string {
  const pins = asArray(
    manifest["definitions"],
    "manifest definitions must be an array",
  ).map((raw) => {
    const definition = asObject(raw, "manifest definition must be an object");
    return {
      ID: asString(definition["id"], "definition id must be a string"),
      Key: asString(definition["key"], "definition key must be a string"),
      Version: asNumber(
        definition["schemaVersion"],
        "definition version must be a number",
      ),
      Fingerprint: [
        ...Buffer.from(
          asString(definition["pinSha256"], "definition pin must be a string"),
          "hex",
        ),
      ],
    };
  });
  const rows = asArray(manifest["rows"], "manifest rows must be an array").map(
    (raw) => {
      const row = asObject(raw, "manifest row must be an object");
      return {
        Sequence: asNumber(row["sequence"], "row sequence must be a number"),
        Target: asString(row["targetId"], "row target must be a string"),
        ExpectedVersion: asNumber(
          row["expectedVersion"],
          "row expected version must be a number",
        ),
        Cells: asArray(row["cells"], "row cells must be an array").map(
          (rawCell) => {
            const cell = asObject(rawCell, "row cell must be an object");
            const presence = asString(
              cell["presence"],
              "cell presence must be a string",
            );
            return {
              Key: asString(cell["key"], "cell key must be a string"),
              Presence:
                presence === "missing" ? 0 : presence === "null" ? 1 : 2,
              Value:
                presence === "missing"
                  ? null
                  : requiredJson(
                      cell["value"],
                      "provided cell value is missing",
                    ),
            };
          },
        ),
      };
    },
  );
  const encoded = JSON.stringify({
    Domain: "periapsis.custom-field-import.v1",
    Tenant: manifest["tenantId"],
    Requester: manifest["requesterId"],
    OwnerMembership: manifest["ownerMembershipId"],
    ObjectType: manifest["objectType"],
    Mode: manifest["mode"] === "dry_run" ? 1 : 2,
    Pins: pins,
    Rows: rows,
    ProjectionVersion: manifest["projectionVersion"],
    MaximumAttempts: manifest["maximumAttempts"],
  });
  return createHash("sha256").update(encoded).digest("hex");
}

function buildManifest(input: {
  id: string;
  tenantId: string;
  requesterId: string;
  ownerMembershipId: string;
  definitions: postgres.JSONValue[];
  rows: postgres.JSONValue[];
  mode?: "commit" | "dry_run";
}): JsonObject {
  const manifest: JsonObject = {
    id: input.id,
    tenantId: input.tenantId,
    requesterId: input.requesterId,
    ownerMembershipId: input.ownerMembershipId,
    objectType: "alert",
    mode: input.mode ?? "commit",
    definitions: input.definitions,
    rows: input.rows,
    requestSha256: digest("placeholder-manifest"),
    projectionVersion: 1,
    maximumAttempts: 5,
  };
  manifest["requestSha256"] = manifestDigest(manifest);
  return manifest;
}

function buildJob(
  manifest: JsonObject,
  requestedAt: string,
  expiresAt: string,
): JsonObject {
  return {
    schemaVersion: 1,
    manifest,
    state: "pending",
    revision: 1,
    attempts: 0,
    results: [],
    requestedAt,
    updatedAt: requestedAt,
    availableAt: requestedAt,
    expiresAt,
    fence: null,
    leaseUntil: null,
    terminalAt: null,
  };
}

function requestCommand(label: string): JsonObject {
  return {
    action: "request",
    keySha256: digest(`request-key:${label}`),
    fingerprintSha256: digest(`request-fingerprint:${label}`),
  };
}

function cancelCommand(label: string): JsonObject {
  return {
    action: "cancel",
    keySha256: digest(`cancel-key:${label}`),
    fingerprintSha256: digest(`cancel-fingerprint:${label}`),
  };
}

function audit(label: string, requestId: string = fixture.request): JsonObject {
  return {
    requestId,
    correlationId: label.startsWith("cancel")
      ? fixture.cancelCorrelation
      : fixture.correlation,
    ipAddress: "127.0.0.1",
    userAgent: `custom-field-import-security/${label}`,
    authenticationMethod: "totp",
  };
}

function workerIdentity(
  serviceAccountId: string,
  workerId = fixture.worker,
): JsonObject {
  return { serviceAccountId, workerId, purpose: "custom_field_import" };
}

function claimJob(
  current: JsonObject,
  workerId: string,
  at: string,
  leaseUntil: string,
): JsonObject {
  const next = structuredClone(current);
  next["state"] = "running";
  next["revision"] = asNumber(current["revision"], "revision is missing") + 1;
  next["attempts"] = asNumber(current["attempts"], "attempts are missing") + 1;
  next["updatedAt"] = at;
  next["availableAt"] = at;
  next["fence"] = workerId;
  next["leaseUntil"] = leaseUntil;
  return next;
}

function appendRowResult(
  current: JsonObject,
  result: JsonObject,
  at: string,
  terminal: boolean,
): JsonObject {
  const next = structuredClone(current);
  next["revision"] = asNumber(current["revision"], "revision is missing") + 1;
  next["results"] = [
    ...asArray(current["results"], "results are missing"),
    result,
  ];
  next["updatedAt"] = at;
  if (terminal) {
    next["state"] = "completed";
    next["fence"] = null;
    next["leaseUntil"] = null;
    next["terminalAt"] = at;
  }
  return next;
}

function cancelPendingJob(current: JsonObject, at: string): JsonObject {
  const next = structuredClone(current);
  const total = asArray(
    asObject(current["manifest"], "manifest is missing")["rows"],
    "manifest rows are missing",
  ).length;
  next["state"] = "cancelled";
  next["revision"] = asNumber(current["revision"], "revision is missing") + 1;
  next["updatedAt"] = at;
  next["results"] = Array.from({ length: total }, (_, index) => ({
    sequence: index + 1,
    outcome: "cancelled",
    resultingVersion: 0,
    fieldErrors: [],
  }));
  next["fence"] = null;
  next["leaseUntil"] = null;
  next["terminalAt"] = at;
  return next;
}

const database = postgres(databaseUrl, { max: 1, onnotice: () => undefined });
const rollbackMarker = new Error(
  "intentional custom-field import security rollback",
);

try {
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe("SET LOCAL statement_timeout = '45s'");

      const [owner] = await transaction<
        {
          rolcanlogin: boolean;
          rolsuper: boolean;
          rolcreaterole: boolean;
          rolcreatedb: boolean;
          rolreplication: boolean;
          rolbypassrls: boolean;
        }[]
      >`
        SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb,
               rolreplication, rolbypassrls
        FROM pg_catalog.pg_roles
        WHERE rolname = 'periapsis_custom_field_import_owner'
      `;
      assert.deepEqual(owner, {
        rolcanlogin: false,
        rolsuper: false,
        rolcreaterole: false,
        rolcreatedb: false,
        rolreplication: false,
        rolbypassrls: false,
      });

      const relationSecurity = await transaction<
        { relname: string; owner: string; rls: boolean; forceRls: boolean }[]
      >`
        SELECT relation.relname,
               pg_get_userbyid(relation.relowner) AS owner,
               relation.relrowsecurity AS rls,
               relation.relforcerowsecurity AS "forceRls"
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relname IN ${transaction(tables)}
        ORDER BY relation.relname
      `;
      assert.equal(relationSecurity.length, tables.length);
      for (const relation of relationSecurity) {
        assert.equal(relation.owner, "periapsis_custom_field_import_owner");
        assert.equal(relation.rls, true);
        assert.equal(relation.forceRls, true);
      }

      const policies = await transaction<
        {
          tablename: string;
          roles: string[];
          qual: string;
          withCheck: string;
        }[]
      >`
        SELECT tablename, roles, qual, with_check AS "withCheck"
        FROM pg_catalog.pg_policies
        WHERE schemaname = 'public' AND tablename IN ${transaction(tables)}
        ORDER BY tablename, policyname
      `;
      assert.equal(policies.length, tables.length);
      for (const policy of policies) {
        assert.deepEqual(policy.roles, ["periapsis_custom_field_import_owner"]);
        assert.match(policy.qual, /tenant_id.*current_setting/u);
        assert.match(policy.withCheck, /tenant_id.*current_setting/u);
        assert.doesNotMatch(policy.qual, /^true$/iu);
        assert.doesNotMatch(policy.withCheck, /^true$/iu);
      }

      for (const role of [
        "periapsis_api",
        "periapsis_worker",
        "periapsis_notifier",
        "periapsis_auditor",
      ] as const) {
        for (const table of tables) {
          // eslint-disable-next-line no-await-in-loop -- ACL proofs are intentionally exhaustive and serialized.
          const [privileges] = await transaction<
            {
              select: boolean;
              insert: boolean;
              update: boolean;
              delete: boolean;
            }[]
          >`
            SELECT has_table_privilege(${role}, ${`public.${table}`}, 'SELECT') AS "select",
                   has_table_privilege(${role}, ${`public.${table}`}, 'INSERT') AS "insert",
                   has_table_privilege(${role}, ${`public.${table}`}, 'UPDATE') AS "update",
                   has_table_privilege(${role}, ${`public.${table}`}, 'DELETE') AS "delete"
          `;
          assert.deepEqual(privileges, {
            select: false,
            insert: false,
            update: false,
            delete: false,
          });
          // eslint-disable-next-line no-await-in-loop -- Every runtime/table pair is an independent real denial proof.
          await expectSqlState(
            asRole(transaction, role, async (sql) => {
              await sql.unsafe(`SELECT * FROM public.${table} LIMIT 1`);
            }),
            "42501",
            `${role} retained direct ${table} access`,
          );
        }
      }

      await transaction`
        INSERT INTO public.tenants (id, slug, name) VALUES
          (${fixture.tenant}::uuid, 'custom-import-security',
           'Custom import security'),
          (${fixture.foreignTenant}::uuid, 'custom-import-security-foreign',
           'Custom import security foreign')
      `;
      await transaction`
        INSERT INTO public.audit_chain_heads (tenant_id) VALUES
          (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
      `;
      await transaction`
        INSERT INTO public.users (id, email, display_name, active) VALUES
          (${fixture.user}::uuid, 'custom-import@example.invalid',
           'Custom import operator', true),
          (${fixture.foreignUser}::uuid, 'custom-import-foreign@example.invalid',
           'Custom import foreign operator', true)
      `;
      await transaction`
        INSERT INTO public.tenant_memberships (
          id, tenant_id, user_id, role, status
        ) VALUES
          (${fixture.membership}::uuid, ${fixture.tenant}::uuid,
           ${fixture.user}::uuid, 'tenant_admin', 'active'),
          (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
           ${fixture.foreignUser}::uuid, 'tenant_admin', 'active')
      `;
      await transaction`
        INSERT INTO public.tenant_user_profiles (
          tenant_id, membership_id, user_id, display_name, email
        ) VALUES
          (${fixture.tenant}::uuid, ${fixture.membership}::uuid,
           ${fixture.user}::uuid, 'Custom import operator',
           'custom-import@example.invalid'),
          (${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid,
           ${fixture.foreignUser}::uuid, 'Custom import foreign operator',
           'custom-import-foreign@example.invalid')
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
      const [sessionWindow] = await transaction<{ now: Date; expires: Date }[]>`
        SELECT date_trunc('milliseconds', transaction_timestamp()) AS now,
               date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour' AS expires
      `;
      assert(sessionWindow, "database session window is missing");
      await transaction`
        INSERT INTO public.auth_sessions (
          id, user_id, rotation_family_id, active_tenant_id,
          token_digest, csrf_secret_digest, authentication_method,
          mfa_satisfied_at, last_seen_at, idle_expires_at,
          absolute_expires_at, created_at
        ) VALUES
          (${fixture.session}::uuid, ${fixture.user}::uuid,
           ${fixture.sessionFamily}::uuid, ${fixture.tenant}::uuid,
           ${Buffer.from(digest("session-token"), "hex")}::bytea,
           ${Buffer.from(digest("session-csrf"), "hex")}::bytea,
           'totp', ${sessionWindow.now}, ${sessionWindow.now}, ${sessionWindow.expires},
           ${sessionWindow.expires}, ${sessionWindow.now}),
          (${fixture.foreignSession}::uuid, ${fixture.foreignUser}::uuid,
           ${fixture.foreignSessionFamily}::uuid, ${fixture.foreignTenant}::uuid,
           ${Buffer.from(digest("foreign-session-token"), "hex")}::bytea,
           ${Buffer.from(digest("foreign-session-csrf"), "hex")}::bytea,
           'totp', ${sessionWindow.now}, ${sessionWindow.now}, ${sessionWindow.expires},
           ${sessionWindow.expires}, ${sessionWindow.now})
      `;
      await transaction`
        SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
               set_config('app.user_id', ${fixture.user}, true),
               set_config('app.service_account_id', '', true)
      `;
      await transaction`
        INSERT INTO public.custom_field_definitions (
          id, tenant_id, object_type, key, label, description, data_type,
          nullable, created_by_membership_id, updated_by_membership_id
        ) VALUES (
          ${fixture.definition}::uuid, ${fixture.tenant}::uuid, 'alert',
          'import_note', 'Import note', 'Custom import runtime proof',
          'short_text', true, ${fixture.membership}::uuid,
          ${fixture.membership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.custom_field_definition_revisions (
          id, tenant_id, definition_id, object_type, schema_version,
          snapshot, created_by_membership_id
        ) VALUES (
          ${fixture.definitionRevision}::uuid, ${fixture.tenant}::uuid,
          ${fixture.definition}::uuid, 'alert', 1,
          ${transaction.json({
            key: "import_note",
            label: "Import note",
            description: "Custom import runtime proof",
            dataType: "short_text",
            required: false,
            nullable: true,
            defaultPresence: "missing",
            constraints: {},
            options: [],
            permissions: [
              {
                audience: "operator",
                canRead: true,
                canCreate: true,
                canUpdate: true,
              },
            ],
            placement: {},
            capabilities: {},
            requiredOnTransitions: [],
          })}::jsonb,
          ${fixture.membership}::uuid
        )
      `;
      await transaction`
        INSERT INTO public.custom_field_permissions (
          tenant_id, definition_id, audience, can_read, can_create, can_update,
          schema_version
        ) VALUES (
          ${fixture.tenant}::uuid, ${fixture.definition}::uuid,
          'operator', true, true, true, 1
        )
      `;
      await transaction`
        INSERT INTO public.alerts (
          id, tenant_id, number, workflow_id, workflow_version, state_key,
          customer_visible, title, description, created_by,
          created_by_membership_id
        )
        SELECT source.id::uuid, ${fixture.tenant}::uuid, source.number,
               workflow.id, workflow.current_version, 'new', false,
               source.title, 'Custom-field import atomicity proof',
               ${fixture.user}::uuid, ${fixture.membership}::uuid
        FROM (VALUES
          (${fixture.alertZero}, 'ALT-2026-925001', 'Zero-cell alert'),
          (${fixture.alertMissing}, 'ALT-2026-925002', 'Missing-cell alert'),
          (${fixture.alertNull}, 'ALT-2026-925003', 'Null-cell alert'),
          (${fixture.alertEmpty}, 'ALT-2026-925004', 'Empty-cell alert')
        ) AS source(id, number, title)
        CROSS JOIN public.ticket_workflows AS workflow
        WHERE workflow.tenant_id = ${fixture.tenant}::uuid
          AND workflow.key = 'default_alert'
      `;

      const [principal] = await transaction<{ id: string }[]>`
        SELECT id::text FROM public.ticket_runtime_service_principals
        WHERE key = 'ticket_runtime' AND enabled
      `;
      let servicePrincipalId = principal?.id;
      if (servicePrincipalId === undefined) {
        const [inserted] = await transaction<{ id: string }[]>`
          INSERT INTO public.ticket_runtime_service_principals (id, key, enabled)
          VALUES (${fixture.fallbackServicePrincipal}::uuid, 'ticket_runtime', true)
          RETURNING id::text
        `;
        assert(inserted, "ticket runtime service principal was not created");
        servicePrincipalId = inserted.id;
      }

      const [definitionRow] = await transaction<
        { document: JsonObject; pin: string }[]
      >`
        SELECT app.private_custom_field_import_definition_document_v1(
                 ${fixture.tenant}::uuid, ${fixture.definition}::uuid
               ) AS document,
               app.private_custom_field_import_definition_pin_v1(
                 ${fixture.tenant}::uuid, ${fixture.definition}::uuid
               ) AS pin
      `;
      assert(
        definitionRow,
        "custom-field import definition projection is missing",
      );
      const definition: JsonObject = {
        ...definitionRow.document,
        pinSha256: definitionRow.pin,
      };
      assert.equal(definition["key"], "import_note");

      const requestedAt = instant(sessionWindow.now);
      const expiresAt = instant(sessionWindow.expires);
      const mainRows: postgres.JSONValue[] = [
        {
          sequence: 1,
          targetId: fixture.alertZero,
          expectedVersion: 1,
          cells: [],
        },
        {
          sequence: 2,
          targetId: fixture.alertMissing,
          expectedVersion: 1,
          cells: [{ key: "import_note", presence: "missing" }],
        },
        {
          sequence: 3,
          targetId: fixture.alertNull,
          expectedVersion: 1,
          cells: [{ key: "import_note", presence: "null", value: null }],
        },
        {
          sequence: 4,
          targetId: fixture.alertEmpty,
          expectedVersion: 1,
          cells: [{ key: "import_note", presence: "present", value: "" }],
        },
      ];
      const mainManifest = buildManifest({
        id: fixture.importJob,
        tenantId: fixture.tenant,
        requesterId: fixture.user,
        ownerMembershipId: fixture.membership,
        definitions: [definition],
        rows: mainRows,
      });
      const mainRequest: JsonObject = {
        schemaVersion: 1,
        job: buildJob(mainManifest, requestedAt, expiresAt),
        scope: "tenant",
        command: requestCommand("main"),
        audit: audit("main"),
      };

      const tamperedPinRequest = structuredClone(mainRequest);
      const tamperedJob = asObject(tamperedPinRequest["job"], "job is missing");
      const tamperedManifest = asObject(
        tamperedJob["manifest"],
        "manifest is missing",
      );
      tamperedManifest["id"] = "01a0b225-0000-7000-8000-000000000611";
      const [tamperedDefinition] = asArray(
        tamperedManifest["definitions"],
        "definitions are missing",
      );
      asObject(tamperedDefinition, "definition is missing")["pinSha256"] =
        digest("tampered-definition-pin");
      tamperedManifest["requestSha256"] = manifestDigest(tamperedManifest);
      tamperedPinRequest["command"] = requestCommand("tampered-pin");
      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_api",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(
              sql,
              "commit_custom_field_import_request_v1",
              tamperedPinRequest,
            ),
        ),
        "40001",
        "a tampered definition pin was accepted",
      );

      const gapRequest = structuredClone(mainRequest);
      const gapJob = asObject(gapRequest["job"], "gap job is missing");
      const gapManifest = asObject(
        gapJob["manifest"],
        "gap manifest is missing",
      );
      gapManifest["id"] = "01a0b225-0000-7000-8000-000000000612";
      asObject(
        asArray(gapManifest["rows"], "gap rows are missing")[0],
        "gap row is missing",
      )["sequence"] = 2;
      gapManifest["requestSha256"] = manifestDigest(gapManifest);
      gapRequest["command"] = requestCommand("sequence-gap");
      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_api",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(
              sql,
              "commit_custom_field_import_request_v1",
              gapRequest,
            ),
        ),
        "22023",
        "a non-contiguous sequence was accepted",
      );

      const mainResult = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_request_v1",
            mainRequest,
          ),
      );
      assert.equal(mainResult["replayed"], false);
      let mainJob = asObject(
        asObject(mainResult["record"], "main record is missing")["job"],
        "main job is missing",
      );
      assert.equal(
        asArray(
          asObject(mainJob["manifest"], "manifest is missing")["rows"],
          "rows are missing",
        ).length,
        4,
      );

      const replay = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_request_v1",
            mainRequest,
          ),
      );
      assert.equal(replay["replayed"], true);
      const conflictingReplay = structuredClone(mainRequest);
      asObject(conflictingReplay["command"], "command is missing")[
        "fingerprintSha256"
      ] = digest("conflicting-request-replay");
      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_api",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(
              sql,
              "commit_custom_field_import_request_v1",
              conflictingReplay,
            ),
        ),
        "23505",
        "a conflicting idempotent request replay was accepted",
      );

      const foreignManifest = buildManifest({
        id: fixture.foreignJob,
        tenantId: fixture.foreignTenant,
        requesterId: fixture.foreignUser,
        ownerMembershipId: fixture.foreignMembership,
        definitions: [],
        rows: [
          {
            sequence: 1,
            targetId: "01a0b225-0000-7000-8000-000000000599",
            expectedVersion: 1,
            cells: [],
          },
        ],
      });
      const foreignRequest: JsonObject = {
        schemaVersion: 1,
        job: buildJob(foreignManifest, requestedAt, expiresAt),
        scope: "tenant",
        command: requestCommand("foreign"),
        audit: {
          ...audit("foreign", "01a0b225-0000-7000-8000-000000000705"),
          correlationId: "01a0b225-0000-7000-8000-000000000706",
        },
      };
      await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.foreignTenant,
        fixture.foreignUser,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_request_v1",
            foreignRequest,
          ),
      );

      const queueResult = await asRole(transaction, "periapsis_worker", (sql) =>
        callFunction(sql, "list_custom_field_import_queues_v1", {
          schemaVersion: 1,
          identity: workerIdentity(servicePrincipalId),
          now: addMilliseconds(requestedAt, 1_000),
          limit: 10,
        }),
      );
      const queues = asArray(
        queueResult["queues"],
        "worker queues are missing",
      );
      assert.equal(queueResult["schemaVersion"], 1);
      assert(
        queues.length >= 2,
        "cross-tenant queue discovery omitted ready work",
      );
      for (const queue of queues) {
        assert.deepEqual(
          Object.keys(asObject(queue, "queue must be an object")).toSorted(),
          ["jobId", "tenantId"],
          "queue discovery leaked job payload",
        );
      }

      const hiddenForeignCount = await asTenantRole(
        transaction,
        "periapsis_custom_field_import_owner",
        fixture.tenant,
        fixture.user,
        async (sql) => {
          const [row] = await sql<{ count: number }[]>`
            SELECT count(*)::integer AS count
            FROM public.custom_field_import_jobs
            WHERE id = ${fixture.foreignJob}::uuid
          `;
          return row?.count;
        },
      );
      assert.equal(
        hiddenForeignCount,
        0,
        "owner RLS exposed a foreign-tenant job",
      );
      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_worker",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(sql, "load_custom_field_import_worker_v1", {
              schemaVersion: 1,
              identity: workerIdentity(servicePrincipalId),
              tenantId: fixture.foreignTenant,
              jobId: fixture.foreignJob,
            }),
        ),
        "42501",
        "worker loaded a job under the wrong tenant transaction",
      );

      const claimAt = addMilliseconds(requestedAt, 1_000);
      const leaseUntil = addMilliseconds(requestedAt, 240_000);
      const claimed = claimJob(mainJob, fixture.worker, claimAt, leaseUntil);
      const claimedRecord = await asTenantRole(
        transaction,
        "periapsis_worker",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(sql, "commit_custom_field_import_transition_v1", {
            schemaVersion: 1,
            identity: workerIdentity(servicePrincipalId),
            tenantId: fixture.tenant,
            jobId: fixture.importJob,
            current: mainJob,
            next: claimed,
          }),
      );
      mainJob = asObject(claimedRecord["job"], "claimed job is missing");

      const rowCommitRequests: JsonObject[] = [];
      const rowDecisions = [
        { outcome: "no_change", resultingVersion: 1, patches: [] },
        { outcome: "no_change", resultingVersion: 1, patches: [] },
        {
          outcome: "committed",
          resultingVersion: 2,
          patches: [
            {
              definitionId: fixture.definition,
              schemaVersion: 1,
              presence: "null",
              canonicalValue: null,
            },
          ],
        },
        {
          outcome: "committed",
          resultingVersion: 2,
          patches: [
            {
              definitionId: fixture.definition,
              schemaVersion: 1,
              presence: "present",
              canonicalValue: "",
            },
          ],
        },
      ] as const;
      for (const [index, decision] of rowDecisions.entries()) {
        const sequence = index + 1;
        // eslint-disable-next-line no-await-in-loop -- Each commit advances the same fenced job revision.
        const rowSnapshot: JsonObject = await asTenantRole<JsonObject>(
          transaction,
          "periapsis_worker",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(sql, "load_custom_field_import_row_v1", {
              schemaVersion: 1,
              identity: workerIdentity(servicePrincipalId),
              tenantId: fixture.tenant,
              jobId: fixture.importJob,
              revision: mainJob["revision"] ?? 0,
              fenceId: fixture.worker,
              sequence,
            }),
        );
        assert.equal(rowSnapshot["foundAndVisible"], true);
        assert.equal(rowSnapshot["allowed"], true);
        assert.equal(rowSnapshot["definitionChanged"], false);
        assert.equal(rowSnapshot["currentVersion"], 1);
        const result: JsonObject = {
          sequence,
          outcome: decision.outcome,
          resultingVersion: decision.resultingVersion,
          fieldErrors: [],
        };
        const recordedAt = addMilliseconds(requestedAt, 2_000 + index * 1_000);
        const next = appendRowResult(
          mainJob,
          result,
          recordedAt,
          sequence === rowDecisions.length,
        );
        const commitRequest: JsonObject = {
          schemaVersion: 1,
          identity: workerIdentity(servicePrincipalId),
          tenantId: fixture.tenant,
          jobId: fixture.importJob,
          fenceId: fixture.worker,
          sequence,
          current: mainJob,
          next,
          result,
          patches: [...decision.patches],
          recordedAt,
        };
        rowCommitRequests.push(commitRequest);
        // eslint-disable-next-line no-await-in-loop -- Each row advances one exact durable CAS revision.
        const stored = await asTenantRole(
          transaction,
          "periapsis_worker",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(
              sql,
              "commit_custom_field_import_row_v1",
              commitRequest,
            ),
        );
        mainJob = asObject(stored["job"], "committed row job is missing");
      }
      assert.equal(mainJob["state"], "completed");
      assert.equal(mainJob["terminalAt"], mainJob["updatedAt"]);

      const replayedRow = await asTenantRole(
        transaction,
        "periapsis_worker",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_row_v1",
            rowCommitRequests[2] ?? {},
          ),
      );
      assert.equal(
        asObject(replayedRow["job"], "replayed job is missing")["state"],
        "completed",
      );
      const conflictingRowReplay = structuredClone(rowCommitRequests[2] ?? {});
      conflictingRowReplay["patches"] = [];
      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_worker",
          fixture.tenant,
          fixture.user,
          (sql) =>
            callFunction(
              sql,
              "commit_custom_field_import_row_v1",
              conflictingRowReplay,
            ),
        ),
        "23505",
        "a conflicting per-row replay was accepted",
      );

      const [atomicEvidence] = await transaction<
        {
          zeroVersion: number;
          missingVersion: number;
          nullVersion: number;
          emptyVersion: number;
          values: number;
          activities: number;
          audits: number;
          outbox: number;
          results: number;
          committed: number;
          noChange: number;
        }[]
      >`
        SELECT
          (SELECT version FROM public.alerts WHERE id=${fixture.alertZero}::uuid) AS "zeroVersion",
          (SELECT version FROM public.alerts WHERE id=${fixture.alertMissing}::uuid) AS "missingVersion",
          (SELECT version FROM public.alerts WHERE id=${fixture.alertNull}::uuid) AS "nullVersion",
          (SELECT version FROM public.alerts WHERE id=${fixture.alertEmpty}::uuid) AS "emptyVersion",
          (SELECT count(*)::integer FROM public.custom_field_values
           WHERE tenant_id=${fixture.tenant}::uuid
             AND alert_id IN (${fixture.alertNull}::uuid,${fixture.alertEmpty}::uuid)) AS values,
          (SELECT count(*)::integer FROM public.ticket_activities
           WHERE tenant_id=${fixture.tenant}::uuid AND kind='custom_field.imported') AS activities,
          (SELECT count(*)::integer FROM public.audit_events
           WHERE tenant_id=${fixture.tenant}::uuid
             AND action='custom_field.import.committed') AS audits,
          (SELECT count(*)::integer FROM public.outbox_events
           WHERE tenant_id=${fixture.tenant}::uuid
             AND event_type='custom_field.import.committed') AS outbox,
          (SELECT count(*)::integer FROM public.custom_field_import_results
           WHERE tenant_id=${fixture.tenant}::uuid
             AND job_id=${fixture.importJob}::uuid) AS results,
          (SELECT committed FROM public.custom_field_import_jobs
           WHERE tenant_id=${fixture.tenant}::uuid
             AND id=${fixture.importJob}::uuid) AS committed,
          (SELECT no_change FROM public.custom_field_import_jobs
           WHERE tenant_id=${fixture.tenant}::uuid
             AND id=${fixture.importJob}::uuid) AS "noChange"
      `;
      assert.deepEqual(atomicEvidence, {
        zeroVersion: 1,
        missingVersion: 1,
        nullVersion: 2,
        emptyVersion: 2,
        values: 2,
        activities: 2,
        audits: 2,
        outbox: 2,
        results: 4,
        committed: 2,
        noChange: 2,
      });
      const storedPresence = await transaction<
        { alertId: string; presence: string; canonical: postgres.JSONValue }[]
      >`
        SELECT alert_id::text AS "alertId", presence::text,
               canonical_value AS canonical
        FROM public.custom_field_values
        WHERE tenant_id=${fixture.tenant}::uuid
          AND definition_id=${fixture.definition}::uuid
        ORDER BY alert_id
      `;
      assert.deepEqual(
        [...storedPresence],
        [
          { alertId: fixture.alertNull, presence: "null", canonical: null },
          { alertId: fixture.alertEmpty, presence: "present", canonical: "" },
        ],
      );

      const resultPage = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(sql, "list_custom_field_import_results_v1", {
            schemaVersion: 1,
            tenantId: fixture.tenant,
            actorId: fixture.user,
            membershipId: fixture.membership,
            objectType: "alert",
            capability: "read",
            scope: "tenant",
            jobId: fixture.importJob,
            after: 0,
            pageSize: 3,
          }),
      );
      assert.equal(
        asArray(resultPage["items"], "result page is missing").length,
        3,
      );
      assert.equal(resultPage["nextAfter"], 3);

      const cancelManifest = buildManifest({
        id: fixture.cancelJob,
        tenantId: fixture.tenant,
        requesterId: fixture.user,
        ownerMembershipId: fixture.membership,
        definitions: [],
        rows: [
          {
            sequence: 1,
            targetId: fixture.alertZero,
            expectedVersion: 1,
            cells: [],
          },
        ],
      });
      const cancelRequest: JsonObject = {
        schemaVersion: 1,
        job: buildJob(cancelManifest, requestedAt, expiresAt),
        scope: "tenant",
        command: requestCommand("pending-cancel"),
        audit: audit("pending-cancel", "01a0b225-0000-7000-8000-000000000707"),
      };
      const pendingCancelCreated = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_request_v1",
            cancelRequest,
          ),
      );
      const pendingCancelJob = asObject(
        asObject(pendingCancelCreated["record"], "cancel record is missing")[
          "job"
        ],
        "cancel job is missing",
      );
      const cancelledAt = addMilliseconds(requestedAt, 10_000);
      const cancelMutation: JsonObject = {
        schemaVersion: 1,
        current: pendingCancelJob,
        next: cancelPendingJob(pendingCancelJob, cancelledAt),
        scope: "tenant",
        command: cancelCommand("pending"),
        audit: audit("cancel-pending", fixture.cancelRequest),
      };
      const cancelled = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_cancellation_v1",
            cancelMutation,
          ),
      );
      assert.equal(cancelled["replayed"], false);
      const cancelledJob = asObject(
        asObject(cancelled["record"], "cancelled record is missing")["job"],
        "cancelled job is missing",
      );
      assert.equal(cancelledJob["state"], "cancelled");
      assert.equal(cancelledJob["terminalAt"], cancelledJob["updatedAt"]);
      const cancelledReplay = await asTenantRole(
        transaction,
        "periapsis_api",
        fixture.tenant,
        fixture.user,
        (sql) =>
          callFunction(
            sql,
            "commit_custom_field_import_cancellation_v1",
            cancelMutation,
          ),
      );
      assert.equal(cancelledReplay["replayed"], true);

      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_api",
          fixture.tenant,
          fixture.user,
          async (sql) => {
            await sql.unsafe(
              "SELECT app.commit_custom_field_import_request_v1(" +
                "jsonb_build_object('padding', repeat('a', 34603009)))",
            );
          },
        ),
        "22023",
        "a highly compressible oversized ABI request bypassed the logical bound",
      );

      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_custom_field_import_owner",
          fixture.tenant,
          fixture.user,
          async (sql) => {
            await sql`
              INSERT INTO public.custom_field_import_rows (
                tenant_id, job_id, sequence, target_id, expected_version,
                cells_snapshot, cells_digest
              ) VALUES (
                ${fixture.tenant}::uuid, ${fixture.importJob}::uuid, 5,
                '01a0b225-0000-7000-8000-000000000598'::uuid, 1,
                jsonb_build_array(jsonb_build_object(
                  'key','oversized','presence','present','value',repeat('a',33554433)
                )), decode(${digest("oversized-cells")}, 'hex')
              )
            `;
          },
        ),
        "23514",
        "a highly compressible oversized cells snapshot bypassed the logical bound",
      );

      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_custom_field_import_owner",
          fixture.tenant,
          fixture.user,
          async (sql) => {
            await sql`
              INSERT INTO public.custom_field_import_command_receipts (
                tenant_id, job_id, actor_user_id, owner_membership_id,
                object_type, action, idempotency_key_digest,
                request_fingerprint_digest, result_snapshot, created_at, expires_at
              ) VALUES (
                ${fixture.tenant}::uuid, ${fixture.importJob}::uuid,
                ${fixture.foreignUser}::uuid, ${fixture.membership}::uuid,
                'alert', 'request', decode(${digest("drift-key")},'hex'),
                decode(${digest("drift-fingerprint")},'hex'), '{}'::jsonb,
                ${sessionWindow.now}, ${sessionWindow.expires}
              )
            `;
          },
        ),
        "23503",
        "a command receipt drifted from its immutable job coordinate",
      );

      await expectSqlState(
        asTenantRole(
          transaction,
          "periapsis_custom_field_import_owner",
          fixture.tenant,
          fixture.user,
          async (sql) => {
            await sql`
              INSERT INTO public.custom_field_import_jobs
              SELECT '01a0b225-0000-7000-8000-000000000613'::uuid,
                     tenant_id, requester_user_id, owner_membership_id,
                     object_type, mode, manifest_snapshot, request_digest,
                     projection_version, maximum_attempts, 'running', 2,
                     1, total, dry_run_valid, committed, no_change,
                     validation_failed, definition_changed, version_conflict,
                     not_found_or_hidden, authorization_denied, cancelled,
                     authorization_revoked, expired, internal_failure,
                     request_id, correlation_id, ip_address, user_agent,
                     authentication_method, requested_at, updated_at,
                     available_at, expires_at, NULL, NULL, NULL
              FROM public.custom_field_import_jobs
              WHERE tenant_id=${fixture.tenant}::uuid
                AND id=${fixture.importJob}::uuid
            `;
          },
        ),
        "23514",
        "a malformed running durable projection bypassed the state constraint",
      );

      for (const table of [
        "custom_field_import_rows",
        "custom_field_import_results",
        "custom_field_import_command_receipts",
      ] as const) {
        // eslint-disable-next-line no-await-in-loop -- Each evidence relation has its own immutable trigger.
        await expectSqlState(
          asTenantRole(
            transaction,
            "periapsis_custom_field_import_owner",
            fixture.tenant,
            fixture.user,
            async (sql) => {
              await sql.unsafe(
                `UPDATE public.${table} SET tenant_id=tenant_id WHERE tenant_id='${fixture.tenant}'::uuid`,
              );
            },
          ),
          "55000",
          `${table} was mutable through UPDATE`,
        );
        // eslint-disable-next-line no-await-in-loop -- Each evidence relation has its own immutable trigger.
        await expectSqlState(
          asTenantRole(
            transaction,
            "periapsis_custom_field_import_owner",
            fixture.tenant,
            fixture.user,
            async (sql) => {
              await sql.unsafe(
                `DELETE FROM public.${table} WHERE tenant_id='${fixture.tenant}'::uuid`,
              );
            },
          ),
          "55000",
          `${table} was mutable through DELETE`,
        );
      }

      throw rollbackMarker;
    }),
    (error) => error === rollbackMarker,
  );
} finally {
  await database.end();
}
