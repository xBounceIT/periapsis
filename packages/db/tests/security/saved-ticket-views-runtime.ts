import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };
type JsonObject = { [key: string]: postgres.JSONValue };

function isJsonObject(
  value: postgres.JSONValue | undefined,
): value is JsonObject {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

function requireJsonObject(
  value: postgres.JSONValue | undefined,
  message: string,
): JsonObject {
  assert(isJsonObject(value), message);
  return value;
}

function requireJsonArray(
  value: postgres.JSONValue | undefined,
  message: string,
): postgres.JSONValue[] {
  assert(Array.isArray(value), message);
  return value;
}

const databaseUrl =
  process.env.PERIAPSIS_SAVED_VIEWS_SECURITY_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_SAVED_VIEWS_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const runSequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d2fc0-1000-7000-8000-${(runSequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(101),
  operatorUser: uuid(102),
  peerUser: uuid(103),
  customerUser: uuid(104),
  foreignUser: uuid(105),
  adminMembership: uuid(201),
  operatorMembership: uuid(202),
  peerMembership: uuid(203),
  customerMembership: uuid(204),
  foreignMembership: uuid(205),
  role: uuid(301),
  foreignRole: uuid(302),
  operatorGrant: uuid(401),
  peerGrant: uuid(402),
  customerGrant: uuid(403),
  foreignGrant: uuid(404),
  replacementGrant: uuid(405),
  contact: uuid(501),
  customDefinition: uuid(601),
  customRevision1: uuid(602),
  customRevision2: uuid(603),
  coreView: uuid(701),
  dynamicView: uuid(702),
} as const;
const fixtureSuffix = runSequence.toString(36);
const fixtureEmail = (label: string): string =>
  `saved-view-${label}-${fixtureSuffix}@example.invalid`;

const sql = postgres(databaseUrl, { max: 6, onnotice: () => undefined });
let identifierSequence = 800;

function nextID(): string {
  identifierSequence += 1;
  return uuid(identifierSequence);
}

function digest(label: string): string {
  return createHash("sha256")
    .update(`saved-ticket-view-runtime:${label}`)
    .digest("hex");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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

async function asApi<T>(
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantID}, true),
             set_config('app.user_id', ${userID}, true),
             set_config('app.service_account_id', '', true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate', 'fixture=value', true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

function coreResolveRequest(
  actorID = fixture.operatorUser,
  ownerMembershipID = fixture.operatorMembership,
): JsonObject {
  return {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    actorId: actorID,
    ownerMembershipId: ownerMembershipID,
    aggregateKind: "alert",
    filters: {
      states: [],
      severities: [],
      priorities: [],
      assignedTeamId: "",
      assigneeUserId: "",
      claimedBy: "",
      queue: "all",
      customerVisible: null,
      search: "private-marker<>&",
      custom: [],
    },
    sort: {
      source: "core",
      coreKey: "updated_at",
      definitionId: "",
      expectedDefinitionVersion: 0,
      direction: "desc",
      nulls: "last",
    },
    columns: [
      {
        source: "core",
        coreKey: "ticket",
        definitionId: "",
        expectedDefinitionVersion: 0,
        width: 0,
        visible: true,
        pin: "none",
      },
    ],
  };
}

function dynamicResolveRequest(): JsonObject {
  const request = coreResolveRequest();
  request.filters = {
    ...requireJsonObject(request.filters, "core filters must be an object"),
    search: "",
    custom: [
      {
        definitionId: fixture.customDefinition,
        expectedDefinitionVersion: 1,
        operator: "eq",
        value: true,
      },
    ],
  };
  request.sort = {
    source: "custom_field",
    coreKey: "",
    definitionId: fixture.customDefinition,
    expectedDefinitionVersion: 1,
    direction: "asc",
    nulls: "last",
  };
  request.columns = [
    ...requireJsonArray(request.columns, "core columns must be an array"),
    {
      source: "custom_field",
      coreKey: "",
      definitionId: fixture.customDefinition,
      expectedDefinitionVersion: 1,
      width: 160,
      visible: true,
      pin: "end",
    },
  ];
  return request;
}

type ResolvedSpec = {
  canonical: string;
  digest: string;
};

async function resolveSpec(
  request: JsonObject,
  tenantID: string = fixture.tenant,
  userID: string = fixture.operatorUser,
): Promise<ResolvedSpec> {
  return asApi(tenantID, userID, async (transaction) => {
    const [row] = await transaction<{ response: JsonObject }[]>`
      SELECT response
      FROM app.resolve_ticket_saved_view_spec_v1(
        ${transaction.json(request)}::jsonb
      )
    `;
    assert(row, "saved-view resolver returned no row");
    assert.equal(row.response["schemaVersion"], 1);
    const encoded = row.response["specCanonicalBase64"];
    const specDigest = row.response["specSha256"];
    assert(typeof encoded === "string");
    assert(typeof specDigest === "string");
    return {
      canonical: Buffer.from(encoded, "base64").toString("utf8"),
      digest: specDigest,
    };
  });
}

type CommitInput = {
  action: "create" | "replace" | "archive" | "restore";
  expectedRevision: number;
  fingerprint: string;
  key: string;
  name: string;
  requestID?: string;
  correlationID?: string;
  spec: ResolvedSpec;
  status: "active" | "archived";
  viewID: string;
};

async function commitView(input: CommitInput): Promise<JsonObject> {
  const commandID = nextID();
  const request: JsonObject = {
    schemaVersion: 1,
    tenantId: fixture.tenant,
    actorId: fixture.operatorUser,
    ownerMembershipId: fixture.operatorMembership,
    aggregateKind: "alert",
    requiredCapability: "saved_view.manage",
    action: input.action,
    viewId: input.viewID,
    expectedRevision: input.expectedRevision,
    nextRevision: input.expectedRevision + 1,
    name: input.name,
    status: input.status,
    specCanonicalBase64: Buffer.from(input.spec.canonical)
      .toString("base64")
      .replace(/=+$/u, ""),
    specSha256: input.spec.digest,
    idempotencyKeySha256: digest(input.key),
    requestFingerprintSha256: digest(input.fingerprint),
    commandId: commandID,
    auditEventId: nextID(),
    outboxEventId: nextID(),
    audit: {
      requestId: input.requestID ?? nextID(),
      correlationId: input.correlationID ?? nextID(),
      remoteAddress: "192.0.2.44",
      userAgent: "saved-ticket-views-runtime",
      authenticationMethod: "totp",
    },
  };
  return asApi(fixture.tenant, fixture.operatorUser, async (transaction) => {
    const [row] = await transaction<{ response: JsonObject }[]>`
      SELECT response
      FROM app.commit_ticket_saved_view_v1(
        ${transaction.json(request)}::jsonb
      )
    `;
    assert(row, "saved-view commit returned no row");
    return row.response;
  });
}

async function getView(
  actorID: string,
  ownerMembershipID: string,
  viewID: string,
  tenantID: string = fixture.tenant,
): Promise<JsonObject[]> {
  return asApi(
    tenantID,
    actorID,
    (transaction) =>
      transaction<{ response: JsonObject }[]>`
      SELECT response
      FROM app.get_ticket_saved_view_v1(${transaction.json({
        schemaVersion: 1,
        tenantId: tenantID,
        actorId: actorID,
        ownerMembershipId: ownerMembershipID,
        aggregateKind: "alert",
        viewId: viewID,
      })}::jsonb)
    `,
  ).then((rows) => rows.map((row) => row.response));
}

async function replayView(
  actorID: string,
  ownerMembershipID: string,
  key: string,
): Promise<JsonObject[]> {
  return asApi(
    fixture.tenant,
    actorID,
    (transaction) =>
      transaction<{ response: JsonObject }[]>`
      SELECT response
      FROM app.lookup_ticket_saved_view_replay_v1(${transaction.json({
        schemaVersion: 1,
        tenantId: fixture.tenant,
        actorId: actorID,
        ownerMembershipId: ownerMembershipID,
        aggregateKind: "alert",
        action: "create",
        idempotencyKeySha256: digest(key),
      })}::jsonb)
    `,
  ).then((rows) => rows.map((row) => row.response));
}

function customSnapshot(version: number): JsonObject {
  return {
    key: "proof_flag",
    label: "Proof flag",
    description: "Runtime proof",
    dataType: "boolean",
    required: false,
    nullable: false,
    defaultPresence: "missing",
    constraints: {},
    options: [],
    permissions: [{ audience: "operator", canRead: true }],
    placement: { showInList: version === 1 },
    capabilities: { filterable: true, sortable: true },
    requiredOnTransitions: [],
  };
}

async function setupFixture(): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction`
      INSERT INTO public.tenants (id, slug, name) VALUES
        (${fixture.tenant}::uuid, ${`saved-view-runtime-${fixtureSuffix}`},
         'Saved view runtime'),
        (${fixture.foreignTenant}::uuid,
         ${`saved-view-runtime-foreign-${fixtureSuffix}`},
         'Saved view runtime foreign')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id) VALUES
        (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name, active) VALUES
        (${fixture.adminUser}::uuid, ${fixtureEmail("admin")}, 'Admin', true),
        (${fixture.operatorUser}::uuid, ${fixtureEmail("operator")}, 'Operator', true),
        (${fixture.peerUser}::uuid, ${fixtureEmail("peer")}, 'Peer', true),
        (${fixture.customerUser}::uuid, ${fixtureEmail("customer")}, 'Customer', true),
        (${fixture.foreignUser}::uuid, ${fixtureEmail("foreign")}, 'Foreign', true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.operatorMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.operatorUser}::uuid, 'read_only', 'active'),
        (${fixture.peerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.peerUser}::uuid, 'customer_user', 'active'),
        (${fixture.customerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.customerUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid, 'read_only', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.foreignTenant}::uuid, ${fixture.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles (
        tenant_id, membership_id, user_id, display_name, email
      ) VALUES
        (${fixture.tenant}::uuid, ${fixture.operatorMembership}::uuid,
         ${fixture.operatorUser}::uuid, 'Operator', ${fixtureEmail("operator")}),
        (${fixture.tenant}::uuid, ${fixture.peerMembership}::uuid,
         ${fixture.peerUser}::uuid, 'Peer', ${fixtureEmail("peer")}),
        (${fixture.tenant}::uuid, ${fixture.customerMembership}::uuid,
         ${fixture.customerUser}::uuid, 'Customer', ${fixtureEmail("customer")})
    `;
    await transaction`
      INSERT INTO public.customer_contacts (
        id, tenant_id, first_name, last_name, email, function, language,
        timezone, contact_class, notification_categories,
        linked_membership_id, linked_user_id
      ) VALUES (
        ${fixture.contact}::uuid, ${fixture.tenant}::uuid, 'Linked', 'Customer',
        ${fixtureEmail("customer")}, 'customer', 'en', 'UTC',
        'standard', ARRAY[]::text[], ${fixture.customerMembership}::uuid,
        ${fixture.customerUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description,
        created_by_membership_id
      ) VALUES
        (${fixture.role}::uuid, ${fixture.tenant}::uuid,
         'saved_view_reader', 'Saved view reader', 'Runtime proof',
         ${fixture.adminMembership}::uuid),
        (${fixture.foreignRole}::uuid, ${fixture.foreignTenant}::uuid,
         'saved_view_reader', 'Saved view reader', 'Runtime proof',
         ${fixture.foreignMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      )
      SELECT role_row.tenant_id::uuid, role_row.role_id::uuid,
             permission.id, 'tenant', role_row.creator::uuid
      FROM (VALUES
        (${fixture.tenant}, ${fixture.role}, ${fixture.adminMembership}),
        (${fixture.foreignTenant}, ${fixture.foreignRole}, ${fixture.foreignMembership})
      ) AS role_row(tenant_id, role_id, creator)
      JOIN public.tenant_permissions AS permission
        ON permission.key = 'alert.read'
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT grant_row.id::uuid, grant_row.tenant_id::uuid,
             grant_row.membership_id::uuid, grant_row.role_id::uuid,
             source.id, grant_row.grantor::uuid, 'Saved view runtime proof'
      FROM (VALUES
        (${fixture.operatorGrant}, ${fixture.tenant}, ${fixture.operatorMembership},
         ${fixture.role}, ${fixture.adminMembership}),
        (${fixture.peerGrant}, ${fixture.tenant}, ${fixture.peerMembership},
         ${fixture.role}, ${fixture.adminMembership}),
        (${fixture.customerGrant}, ${fixture.tenant}, ${fixture.customerMembership},
         ${fixture.role}, ${fixture.adminMembership}),
        (${fixture.foreignGrant}, ${fixture.foreignTenant}, ${fixture.foreignMembership},
         ${fixture.foreignRole}, ${fixture.foreignMembership})
      ) AS grant_row(id, tenant_id, membership_id, role_id, grantor)
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = grant_row.tenant_id::uuid
       AND source.key = 'manual' AND source.kind = 'manual'
       AND source.retired_at IS NULL
    `;
    await transaction`
      INSERT INTO public.custom_field_definitions (
        id, tenant_id, object_type, key, label, description, data_type,
        show_in_list, filterable, sortable,
        created_by_membership_id, updated_by_membership_id
      ) VALUES (
        ${fixture.customDefinition}::uuid, ${fixture.tenant}::uuid, 'alert',
        'proof_flag', 'Proof flag', 'Runtime proof', 'boolean',
        true, true, true, ${fixture.adminMembership}::uuid,
        ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.custom_field_definition_revisions (
        id, tenant_id, definition_id, object_type, schema_version,
        snapshot, created_by_membership_id
      ) VALUES (
        ${fixture.customRevision1}::uuid, ${fixture.tenant}::uuid,
        ${fixture.customDefinition}::uuid, 'alert', 1,
        ${transaction.json(customSnapshot(1))}::jsonb,
        ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.custom_field_permissions (
        tenant_id, definition_id, audience, can_read, can_create, can_update,
        schema_version
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.customDefinition}::uuid,
        'operator', true, false, false, 1
      )
    `;
  });
}

async function assertSavedSortIndexes(): Promise<void> {
  const plans = [
    ["boolean", "boolean_value"],
    ["date", "date_value"],
    ["ip", "ip_value"],
    ["cidr", "cidr_value"],
    ["reference", "reference_id"],
    ["single_select", "option_keys[1]"],
  ] as const;
  await sql.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL enable_seqscan = off");
    const queryPlans = await Promise.all(
      plans.map(async ([suffix, expression]) => {
        const indexName = `custom_field_values_saved_sort_${suffix}_idx`;
        const rows = await transaction.unsafe<{ "QUERY PLAN": string }[]>(
          `EXPLAIN (COSTS OFF) SELECT alert_id, case_id
         FROM public.custom_field_values
         WHERE tenant_id = '${fixture.tenant}'::uuid
           AND object_type = 'alert'
           AND definition_id = '${fixture.customDefinition}'::uuid
           AND definition_schema_version = 1
         ORDER BY ${expression}, alert_id, case_id
         LIMIT 100`,
        );
        return {
          indexName,
          plan: rows.map((row) => row["QUERY PLAN"]).join("\n"),
        };
      }),
    );
    for (const { indexName, plan } of queryPlans) {
      assert(
        plan.includes(indexName),
        `${indexName} did not support its saved-view sort plan:\n${plan}`,
      );
    }
  });
}

try {
  const [server] = await sql<{ version: string }[]>`
    SELECT current_setting('server_version') AS version
  `;
  assert(
    server?.version.startsWith("18."),
    "runtime harness requires PostgreSQL 18",
  );
  const [readiness] = await sql<
    { ready: boolean; retired_predecessor_ready: boolean }[]
  >`
    SELECT app.release_runtime_schema_readiness_v59() AS ready,
           app.ticket_saved_views_schema_readiness_v1()
             AS retired_predecessor_ready
  `;
  assert.deepEqual(readiness, {
    ready: true,
    retired_predecessor_ready: false,
  });
  await setupFixture();
  await assertSavedSortIndexes();

  const coreSpec = await resolveSpec(coreResolveRequest());
  assert.equal(
    coreSpec.canonical,
    '{"version":1,"filters":{"states":[],"severities":[],"priorities":[],"queue":"all","search":"private-marker\\u003c\\u003e\\u0026","custom":[]},"sort":{"source":"core","coreKey":"updated_at","direction":"desc","nulls":"last"},"columns":[{"source":"core","coreKey":"ticket","width":0,"visible":true,"pin":"none"}]}',
    "SQL canonical encoding drifted from encoding/json ordering/escaping",
  );
  assert.equal(sha256(coreSpec.canonical), coreSpec.digest);
  await Promise.all(
    [
      { requestID: "00000000-0000-4000-8000-000000000001" },
      { correlationID: "00000000-0000-4000-8000-000000000002" },
    ].map((auditOverride) =>
      expectSqlState(
        commitView({
          action: "create",
          expectedRevision: 0,
          fingerprint: "invalid-audit-identifier",
          key: "invalid-audit-identifier",
          name: "Invalid audit identifier",
          spec: coreSpec,
          status: "active",
          viewID: nextID(),
          ...auditOverride,
        }),
        "22023",
        "a non-UUIDv7 audit identifier was accepted",
      ),
    ),
  );

  const create = await commitView({
    action: "create",
    expectedRevision: 0,
    fingerprint: "create-core",
    key: "create-core",
    name: "Private marker view",
    spec: coreSpec,
    status: "active",
    viewID: fixture.coreView,
  });
  assert.equal(create["replayed"], false);
  assert.equal(
    requireJsonObject(create["record"], "create record must be an object")[
      "revision"
    ],
    1,
  );

  const replay = await commitView({
    action: "create",
    expectedRevision: 0,
    fingerprint: "create-core",
    key: "create-core",
    name: "Private marker view",
    spec: coreSpec,
    status: "active",
    viewID: fixture.dynamicView,
  });
  assert.equal(replay["replayed"], true);
  assert.equal(
    requireJsonObject(replay["record"], "replay record must be an object")[
      "id"
    ],
    fixture.coreView,
  );
  await expectSqlState(
    commitView({
      action: "create",
      expectedRevision: 0,
      fingerprint: "divergent-create",
      key: "create-core",
      name: "Divergent",
      spec: coreSpec,
      status: "active",
      viewID: fixture.dynamicView,
    }),
    "23505",
    "a divergent idempotency replay was accepted",
  );

  const replayLookup = await replayView(
    fixture.operatorUser,
    fixture.operatorMembership,
    "create-core",
  );
  assert.equal(
    requireJsonObject(
      replayLookup[0]?.["record"],
      "lookup replay record must be an object",
    )["revision"],
    1,
  );
  assert.deepEqual(
    await getView(fixture.peerUser, fixture.peerMembership, fixture.coreView),
    [],
    "an authorized peer observed another owner's view",
  );
  await expectSqlState(
    getView(fixture.customerUser, fixture.customerMembership, fixture.coreView),
    "42501",
    "an exact linked customer with an operator grant used the operator ABI",
  );
  await expectSqlState(
    getView(
      fixture.operatorUser,
      fixture.operatorMembership,
      fixture.coreView,
      fixture.foreignTenant,
    ),
    "42501",
    "a mismatched tenant context reached resource lookup",
  );

  await sql`
    UPDATE public.tenant_membership_role_grants
    SET revoked_at = clock_timestamp(),
        revoked_by_membership_id = ${fixture.adminMembership}::uuid,
        revoke_reason = 'Runtime revocation proof',
        version = version + 1,
        updated_at = clock_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.operatorGrant}::uuid
  `;
  await expectSqlState(
    replayView(fixture.operatorUser, fixture.operatorMembership, "create-core"),
    "42501",
    "revocation between commit and replay did not fail closed",
  );
  await sql`
    INSERT INTO public.tenant_membership_role_grants (
      id, tenant_id, membership_id, role_id, source_id,
      granted_by_membership_id, grant_reason
    )
    SELECT ${fixture.replacementGrant}::uuid, ${fixture.tenant}::uuid,
           ${fixture.operatorMembership}::uuid, ${fixture.role}::uuid,
           source.id, ${fixture.adminMembership}::uuid,
           'Runtime authorization restoration'
    FROM public.tenant_authorization_sources AS source
    WHERE source.tenant_id = ${fixture.tenant}::uuid
      AND source.key = 'manual' AND source.kind = 'manual'
      AND source.retired_at IS NULL
  `;

  const replacements = await Promise.allSettled([
    commitView({
      action: "replace",
      expectedRevision: 1,
      fingerprint: "replace-a",
      key: "replace-a",
      name: "CAS winner A",
      spec: coreSpec,
      status: "active",
      viewID: fixture.coreView,
    }),
    commitView({
      action: "replace",
      expectedRevision: 1,
      fingerprint: "replace-b",
      key: "replace-b",
      name: "CAS winner B",
      spec: coreSpec,
      status: "active",
      viewID: fixture.coreView,
    }),
  ]);
  assert.equal(
    replacements.filter((result) => result.status === "fulfilled").length,
    1,
    "the revision CAS did not produce one winner",
  );
  const rejected = replacements.find((result) => result.status === "rejected");
  assert(rejected?.status === "rejected");
  assertSqlState(rejected.reason, "40001");
  const createSnapshot = await replayView(
    fixture.operatorUser,
    fixture.operatorMembership,
    "create-core",
  );
  assert.equal(
    requireJsonObject(
      createSnapshot[0]?.["record"],
      "create snapshot record must be an object",
    )["revision"],
    1,
    "later mutations changed the immutable replay snapshot",
  );

  const dynamicSpec = await resolveSpec(dynamicResolveRequest());
  await commitView({
    action: "create",
    expectedRevision: 0,
    fingerprint: "create-dynamic",
    key: "create-dynamic",
    name: "Dynamic proof",
    spec: dynamicSpec,
    status: "active",
    viewID: fixture.dynamicView,
  });
  await sql.begin(async (transaction) => {
    await transaction`
      UPDATE public.custom_field_definitions
      SET show_in_list = false, schema_version = 2,
          updated_by_membership_id = ${fixture.adminMembership}::uuid,
          updated_at = clock_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.customDefinition}::uuid
    `;
    await transaction`
      UPDATE public.custom_field_permissions
      SET schema_version = 2, updated_at = clock_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND definition_id = ${fixture.customDefinition}::uuid
        AND audience = 'operator'
    `;
    await transaction`
      INSERT INTO public.custom_field_definition_revisions (
        id, tenant_id, definition_id, object_type, schema_version,
        snapshot, created_by_membership_id
      ) VALUES (
        ${fixture.customRevision2}::uuid, ${fixture.tenant}::uuid,
        ${fixture.customDefinition}::uuid, 'alert', 2,
        ${transaction.json(customSnapshot(2))}::jsonb,
        ${fixture.adminMembership}::uuid
      )
    `;
  });
  await expectSqlState(
    resolveSpec(dynamicResolveRequest()),
    "55000",
    "a stale or hidden custom definition was resolved",
  );
  const archived = await commitView({
    action: "archive",
    expectedRevision: 1,
    fingerprint: "archive-stale-dynamic",
    key: "archive-stale-dynamic",
    name: "Dynamic proof",
    spec: dynamicSpec,
    status: "archived",
    viewID: fixture.dynamicView,
  });
  assert.equal(
    requireJsonObject(archived["record"], "archive record must be an object")[
      "status"
    ],
    "archived",
  );
  await expectSqlState(
    commitView({
      action: "restore",
      expectedRevision: 2,
      fingerprint: "restore-stale-dynamic",
      key: "restore-stale-dynamic",
      name: "Dynamic proof",
      spec: dynamicSpec,
      status: "active",
      viewID: fixture.dynamicView,
    }),
    "55000",
    "restore accepted a stale hidden definition pin",
  );

  const [redaction] = await sql<
    { audit_text: string; outbox_text: string; raw_keys: string }[]
  >`
    SELECT
      coalesce(string_agg(audit.metadata::text || audit.after::text, ''), '')
        AS audit_text,
      coalesce(string_agg(outbox.payload::text, ''), '') AS outbox_text,
      coalesce(string_agg(encode(command.idempotency_key_digest, 'hex'), ''), '')
        AS raw_keys
    FROM public.ticket_saved_views AS view_record
    LEFT JOIN public.audit_events AS audit
      ON audit.tenant_id = view_record.tenant_id
     AND audit.resource_id = view_record.id
    LEFT JOIN public.outbox_events AS outbox
      ON outbox.tenant_id = view_record.tenant_id
     AND outbox.aggregate_id = view_record.id
    LEFT JOIN public.ticket_saved_view_commands AS command
      ON command.tenant_id = view_record.tenant_id
     AND command.result_view_id = view_record.id
    WHERE view_record.tenant_id = ${fixture.tenant}::uuid
  `;
  assert(redaction);
  assert(!redaction.audit_text.includes("private-marker"));
  assert(!redaction.outbox_text.includes("private-marker"));
  assert(!redaction.audit_text.includes("Private marker view"));
  assert(!redaction.outbox_text.includes("Private marker view"));
  assert(!redaction.audit_text.includes(coreSpec.digest));
  assert(!redaction.outbox_text.includes(coreSpec.digest));
  assert(!redaction.raw_keys.includes("create-core"));

  await expectSqlState(
    asApi(
      fixture.tenant,
      fixture.operatorUser,
      (transaction) =>
        transaction`SELECT count(*) FROM public.ticket_saved_views`,
    ),
    "42501",
    "the API runtime received direct saved-view table access",
  );
  const [acl] = await sql<{ api_table: boolean; notifier_function: boolean }[]>`
    SELECT has_table_privilege(
             'periapsis_api', 'public.ticket_saved_views', 'SELECT'
           ) AS api_table,
           has_function_privilege(
             'periapsis_notifier',
             'app.get_ticket_saved_view_v1(jsonb)', 'EXECUTE'
           ) AS notifier_function
  `;
  assert.deepEqual(acl, { api_table: false, notifier_function: false });
} finally {
  await sql.end();
}
