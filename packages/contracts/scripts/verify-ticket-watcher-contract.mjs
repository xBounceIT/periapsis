import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const generatedSdk = readFileSync(
  resolve(repositoryRoot, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);
const generatedTypes = readFileSync(
  resolve(
    repositoryRoot,
    "packages/contracts/generated/typescript/types.gen.ts",
  ),
  "utf8",
);
const generatedGo = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error("Ticket-watcher contract invariant failed: " + message);
};

const assert = (condition, message) => {
  if (!condition) fail(message);
};

const exact = (actual, expected, message) => {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    message + ": received " + JSON.stringify(actual),
  );
};

const scopes = ["own", "assigned", "operator_team", "tenant"];
const uuidV7Pattern =
  "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])";
const mutationStatuses = [
  "200",
  "400",
  "401",
  "403",
  "404",
  "409",
  "412",
  "428",
  "503",
];
const operations = [
  {
    kind: "Alert",
    collection: "/api/v1/tenants/{tenantId}/alerts/{alertId}/watchers",
    member: "/api/v1/tenants/{tenantId}/alerts/{alertId}/watchers/{userId}",
    idParameter: "#/components/parameters/AlertId",
    permissionPrefix: "alert",
  },
  {
    kind: "Case",
    collection: "/api/v1/tenants/{tenantId}/cases/{caseId}/watchers",
    member: "/api/v1/tenants/{tenantId}/cases/{caseId}/watchers/{userId}",
    idParameter: "#/components/parameters/CaseId",
    permissionPrefix: "case",
  },
];

for (const expected of operations) {
  const collection = document.paths?.[expected.collection];
  exact(
    collection?.parameters?.map((parameter) => parameter.$ref),
    ["#/components/parameters/TenantId", expected.idParameter],
    expected.kind + " watcher collection coordinates drifted",
  );
  const read = collection?.get;
  assert(read !== undefined, "GET " + expected.collection + " is missing");
  exact(
    read.operationId,
    "getTenant" + expected.kind + "Watchers",
    expected.kind + " watcher read operationId drifted",
  );
  exact(
    read.security,
    [{ sessionCookie: [] }],
    expected.kind + " watcher read authentication drifted",
  );
  assert(
    read.requestBody === undefined,
    expected.kind + " watcher read must not accept a body",
  );
  const readAuthorization = read["x-periapsis-authorization"];
  assert(
    readAuthorization?.tenantContext === "path" &&
      readAuthorization.activeMembership === true &&
      readAuthorization.permission === expected.permissionPrefix + ".read" &&
      readAuthorization.uiVisibilityIsNotAuthorization === true &&
      readAuthorization.projection === "operator_only",
    expected.kind + " watcher read live authority drifted",
  );
  exact(
    readAuthorization?.scopes,
    scopes,
    expected.kind + " read scopes drifted",
  );
  exact(
    readAuthorization?.principalTypes,
    ["human"],
    expected.kind + " read principal types drifted",
  );
  exact(
    readAuthorization?.actorKinds,
    ["operator"],
    expected.kind + " read actor kinds drifted",
  );
  exact(
    Object.keys(read.responses ?? {}),
    ["200", "400", "401", "403", "404", "503"],
    expected.kind + " watcher read outcomes drifted",
  );
  assertWatcherSuccess(read.responses["200"], false, expected.kind + " read");
  assertNoStoreErrors(read.responses, ["400", "401", "403", "404", "503"]);

  const member = document.paths?.[expected.member];
  exact(
    member?.parameters?.map((parameter) => parameter.$ref),
    [
      "#/components/parameters/TenantId",
      expected.idParameter,
      "#/components/parameters/UserId",
    ],
    expected.kind + " watcher member coordinates drifted",
  );
  for (const mutation of [
    {
      method: "put",
      verb: "Add",
      target:
        "active_tenant_operator_with_live_" +
        expected.permissionPrefix +
        "_read",
    },
    {
      method: "delete",
      verb: "Remove",
      target: "existing_watcher_even_if_inactive",
    },
  ]) {
    const operation = member?.[mutation.method];
    const label = expected.kind + " watcher " + mutation.method.toUpperCase();
    assert(operation !== undefined, label + " is missing");
    exact(
      operation.operationId,
      mutation.verb.toLowerCase() + "Tenant" + expected.kind + "Watcher",
      label + " operationId drifted",
    );
    exact(
      operation.security,
      [{ sessionCookie: [], csrfToken: [] }],
      label + " authentication or CSRF drifted",
    );
    exact(
      operation.parameters?.map((parameter) => parameter.$ref),
      [
        "#/components/parameters/TicketWatcherIfMatch",
        "#/components/parameters/IdempotencyKey",
      ],
      label + " concurrency or idempotency headers drifted",
    );
    assert(
      operation.requestBody === undefined,
      label + " must not accept a body",
    );
    const authorization = operation["x-periapsis-authorization"];
    assert(
      authorization?.tenantContext === "path" &&
        authorization.activeMembership === true &&
        authorization.permission === expected.permissionPrefix + ".update" &&
        authorization.uiVisibilityIsNotAuthorization === true &&
        authorization.projection === "operator_only" &&
        authorization.targetEligibility === mutation.target &&
        authorization.idempotencyReplay === "immutable_command_result",
      label + " live authority, target eligibility, or replay metadata drifted",
    );
    exact(authorization?.scopes, scopes, label + " scopes drifted");
    exact(
      authorization?.principalTypes,
      ["human"],
      label + " principals drifted",
    );
    exact(authorization?.actorKinds, ["operator"], label + " actors drifted");
    exact(
      Object.keys(operation.responses ?? {}),
      mutationStatuses,
      label + " outcomes drifted",
    );
    assertWatcherSuccess(operation.responses["200"], true, label);
    assertNoStoreErrors(operation.responses, mutationStatuses.slice(1));
    assert(
      operation.description.includes("set-idempotent no-op") &&
        operation.description.includes("unchanged page and version"),
      label + " must preserve successful set-idempotent no-op semantics",
    );
    if (mutation.method === "delete") {
      assert(
        operation.description.includes("inactive") &&
          operation.description.includes("no longer eligible"),
        label + " must allow cleanup of an ineligible existing watcher",
      );
    } else {
      assert(
        operation.description.includes("active member") &&
          /human\s+operator/u.test(operation.description) &&
          /live\s+scoped/u.test(operation.description),
        label + " must require live eligible operator resolution",
      );
    }
  }
}

function assertWatcherSuccess(response, replayHeader, label) {
  assert(
    response?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      response.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
      response.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/TicketWatcherPage",
    label + " projection, ETag, or cache policy drifted",
  );
  assert(
    (response.headers?.["X-Idempotent-Replay"]?.$ref ===
      "#/components/headers/IdempotentReplay") ===
      replayHeader,
    label + " replay header drifted",
  );
}

function assertNoStoreErrors(responses, statuses) {
  for (const status of statuses) {
    const reference = responses[status]?.$ref;
    assert(
      reference?.startsWith("#/components/responses/NoStore") === true,
      status + " watcher response must remain no-store",
    );
    const name = reference.slice("#/components/responses/".length);
    assert(
      document.components.responses[name]?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
      status + " watcher response no-store header drifted",
    );
  }
}

const userIdParameter = document.components.parameters.UserId;
assert(
  userIdParameter.required === true &&
    userIdParameter.in === "path" &&
    userIdParameter.schema?.type === "string" &&
    userIdParameter.schema.format === "uuid" &&
    userIdParameter.schema.minLength === 36 &&
    userIdParameter.schema.maxLength === 36 &&
    userIdParameter.schema.pattern === uuidV7Pattern,
  "watcher target userId must remain a canonical UUIDv7 path coordinate",
);
for (const parameterName of ["TenantId", "AlertId", "CaseId"]) {
  const parameter = document.components.parameters[parameterName];
  assert(
    parameter.required === true &&
      parameter.in === "path" &&
      parameter.schema?.type === "string" &&
      parameter.schema.format === "uuid" &&
      parameter.schema.minLength === 36 &&
      parameter.schema.maxLength === 36 &&
      parameter.schema.pattern === uuidV7Pattern,
    parameterName + " must remain a canonical UUIDv7 watcher coordinate",
  );
}
const uuidV7 = new RegExp(uuidV7Pattern, "u");
for (const accepted of ["0198c97d-cf4f-7000-8000-000000000041"]) {
  assert(uuidV7.test(accepted), "UUIDv7 rejected " + accepted);
}
for (const rejected of [
  "0198c97d-cf4f-4000-8000-000000000041",
  "0198C97D-CF4F-7000-8000-000000000041",
  "0198c97d-cf4f-7000-7000-000000000041",
  "0198c97d-cf4f-7000-8000-000000000041\n",
]) {
  assert(!uuidV7.test(rejected), "UUIDv7 accepted " + JSON.stringify(rejected));
}

const watcher = document.components.schemas.TicketWatcher;
const displayNamePattern =
  "^(?![\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000])(?![\\s\\S]*[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000](?![\\s\\S]))(?:[^\\u0000-\\u001F\\u007F-\\u009F\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069\\uD800-\\uDFFF]|[\\uD800-\\uDBFF][\\uDC00-\\uDFFF])+(?![\\s\\S])";
exact(
  watcher.required,
  ["userId", "displayName", "addedAt"],
  "watcher allowlist drifted",
);
exact(
  Object.keys(watcher.properties),
  ["userId", "displayName", "addedAt"],
  "watcher property set drifted",
);
assert(
  watcher.additionalProperties === false,
  "watcher must reject unknown fields",
);
assert(
  watcher.properties.userId.type === "string" &&
    watcher.properties.userId.format === "uuid" &&
    watcher.properties.userId.minLength === 36 &&
    watcher.properties.userId.maxLength === 36 &&
    watcher.properties.userId.pattern === uuidV7Pattern &&
    watcher.properties.displayName.type === "string" &&
    watcher.properties.displayName.minLength === 1 &&
    watcher.properties.displayName.maxLength === 160 &&
    watcher.properties.displayName.pattern === displayNamePattern &&
    watcher.properties.addedAt.type === "string" &&
    watcher.properties.addedAt.format === "date-time",
  "watcher identity or bounds drifted",
);
const displayName = new RegExp(displayNamePattern, "u");
for (const accepted of [
  "Operator One",
  "\uFEFFOperator\uFEFF",
  "A\u2003B",
  "Operator 😀",
]) {
  assert(
    displayName.test(accepted),
    "display name rejected " + JSON.stringify(accepted),
  );
}
for (const rejected of [
  " Operator",
  "Operator\u3000",
  "Operator\nName",
  "Operator\u0085Name",
  "Operator\u200eName",
  "Operator\u202eName",
  "Operator\u2066Name",
  String.fromCharCode(0xd800),
  "Operator" + String.fromCharCode(0xdc00),
]) {
  assert(
    !displayName.test(rejected),
    "display name accepted " + JSON.stringify(rejected),
  );
}
for (const forbidden of ["email", "contactId", "tenantId", "membershipId"]) {
  assert(
    watcher.properties[forbidden] === undefined,
    "watcher leaked forbidden identity field " + forbidden,
  );
}

const page = document.components.schemas.TicketWatcherPage;
exact(
  page.required,
  ["items", "version", "updatedAt"],
  "page allowlist drifted",
);
exact(
  Object.keys(page.properties),
  ["items", "version", "updatedAt"],
  "page property set drifted",
);
assert(page.additionalProperties === false, "page must reject unknown fields");
assert(
  page.properties.items.maxItems === 1000 &&
    page.properties.items.uniqueItems === true &&
    page.properties.items.items.$ref === "#/components/schemas/TicketWatcher" &&
    page.properties.items.description.includes(
      'displayName COLLATE "C", then userId',
    ) &&
    page.properties.items.description.includes("exactly once") &&
    !page.properties.items.description.includes("lower(") &&
    page.properties.version.$ref === "#/components/schemas/ResourceVersion" &&
    page.properties.updatedAt.type === "string" &&
    page.properties.updatedAt.format === "date-time",
  "page cardinality, canonical order, version, or timestamp drifted",
);

const schemas = document.components.schemas;
const watcherEtagPattern =
  '^"v(?:[1-9][0-9]{0,8}|1[0-9]{9}|20[0-9]{8}|21[0-3][0-9]{7}|214[0-6][0-9]{6}|2147[0-3][0-9]{5}|21474[0-7][0-9]{4}|214748[0-2][0-9]{3}|2147483[0-5][0-9]{2}|21474836[0-3][0-9]|214748364[0-6])"(?![\\s\\S])';
assert(
  document.components.parameters.TicketWatcherIfMatch.schema.$ref ===
    "#/components/schemas/TicketWatcherStrongEntityTag" &&
    schemas.TicketWatcherStrongEntityTag.minLength === 4 &&
    schemas.TicketWatcherStrongEntityTag.maxLength === 13 &&
    schemas.TicketWatcherStrongEntityTag.pattern === watcherEtagPattern,
  "watcher CAS bounds drifted",
);
const watcherEtag = new RegExp(watcherEtagPattern, "u");
for (const accepted of ['"v1"', '"v2147483646"']) {
  assert(watcherEtag.test(accepted), "watcher ETag rejected " + accepted);
}
for (const rejected of ['"v0"', '"v01"', '"v2147483647"', 'W/"v1"', '"v1"\n']) {
  assert(!watcherEtag.test(rejected), "watcher ETag accepted " + rejected);
}
exact(
  document.components.headers.IdempotentReplay.schema.enum,
  ["true", "false"],
  "replay header grammar drifted",
);
assert(
  document.components.headers.IdempotentReplay.required === true,
  "replay header must remain required",
);

for (const expected of operations) {
  for (const verb of ["get", "add", "remove"]) {
    const operationId =
      verb + "Tenant" + expected.kind + "Watcher" + (verb === "get" ? "s" : "");
    assert(
      generatedSdk.includes("export const " + operationId + " ="),
      "generated TypeScript SDK is missing " + operationId,
    );
  }
  for (const verb of ["Add", "Remove"]) {
    const symbol = verb + "Tenant" + expected.kind + "WatcherData";
    assert(
      generatedTypes.includes("export type " + symbol + " ="),
      "generated TypeScript type is missing " + symbol,
    );
  }
}
for (const symbol of [
  "TicketWatcher",
  "TicketWatcherPage",
  "TicketWatcherIfMatch",
  "TicketWatcherStrongEntityTag",
]) {
  assert(
    generatedTypes.includes("export type " + symbol + " ="),
    "generated TypeScript type is missing " + symbol,
  );
}
assert(
  generatedGo.includes("type TicketWatcher struct {") &&
    generatedGo.includes("type TicketWatcherPage struct {") &&
    generatedGo.includes(
      "type TicketWatcherIfMatch = TicketWatcherStrongEntityTag",
    ),
  "generated Go watcher models drifted",
);
for (const expected of operations) {
  const idType = expected.kind + "Id";
  assert(
    generatedGo.includes(
      "GetTenant" +
        expected.kind +
        "Watchers(w http.ResponseWriter, r *http.Request, tenantId TenantId, " +
        expected.permissionPrefix +
        "Id " +
        idType +
        ")",
    ),
    "generated Go " + expected.kind + " watcher read signature drifted",
  );
  for (const verb of ["Add", "Remove"]) {
    const operation = verb + "Tenant" + expected.kind + "Watcher";
    assert(
      generatedGo.includes(
        operation +
          "(w http.ResponseWriter, r *http.Request, tenantId TenantId, " +
          expected.permissionPrefix +
          "Id " +
          idType +
          ", userId UserId, params " +
          operation +
          "Params)",
      ),
      "generated Go " + operation + " signature drifted",
    );
  }
}

process.stdout.write("Ticket-watcher contract invariants verified.\n");
