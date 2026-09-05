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

const fail = (message) => {
  throw new Error("Ticket-metadata contract invariant failed: " + message);
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

const schemas = document.components.schemas;
const singleLinePattern =
  "^(?![\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000])(?![\\s\\S]*[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000](?![\\s\\S]))[^\\u0000-\\u001F\\u007F-\\u009F]+(?![\\s\\S])";
const multilinePattern =
  "^(?:(?![\\s\\S])|(?![\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000])(?![\\s\\S]*[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000](?![\\s\\S]))[^\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F]+(?![\\s\\S]))";
const singleLine = new RegExp(singleLinePattern, "u");
const multiline = new RegExp(multilinePattern, "u");

const operations = [
  {
    kind: "Alert",
    path: "/api/v1/tenants/{tenantId}/alerts/{alertId}/metadata",
    idParameter: "#/components/parameters/AlertId",
    operationId: "replaceTenantAlertMetadata",
    permission: "alert.update",
  },
  {
    kind: "Case",
    path: "/api/v1/tenants/{tenantId}/cases/{caseId}/metadata",
    idParameter: "#/components/parameters/CaseId",
    operationId: "replaceTenantCaseMetadata",
    permission: "case.update",
  },
];

for (const expected of operations) {
  const pathItem = document.paths?.[expected.path];
  const operation = pathItem?.put;
  assert(operation !== undefined, "PUT " + expected.path + " is missing");
  exact(
    pathItem.parameters?.map((parameter) => parameter.$ref),
    ["#/components/parameters/TenantId", expected.idParameter],
    expected.kind + " metadata path coordinates drifted",
  );
  exact(
    operation.operationId,
    expected.operationId,
    expected.kind + " metadata operationId drifted",
  );
  exact(
    operation.security,
    [{ sessionCookie: [], csrfToken: [] }],
    expected.kind + " metadata authentication or CSRF drifted",
  );
  exact(
    operation.parameters?.map((parameter) => parameter.$ref),
    [
      "#/components/parameters/MetadataIfMatch",
      "#/components/parameters/IdempotencyKey",
    ],
    expected.kind + " metadata concurrency or idempotency headers drifted",
  );
  exact(
    operation.requestBody?.content?.["application/json"]?.schema?.$ref,
    "#/components/schemas/" + expected.kind + "MetadataReplaceRequest",
    expected.kind + " metadata request schema drifted",
  );
  assert(
    operation.requestBody?.required === true,
    expected.kind + " metadata request body must remain required",
  );
  const authorization = operation["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === expected.permission &&
      authorization.uiVisibilityIsNotAuthorization === true &&
      authorization.projection === "operator_only" &&
      authorization.idempotencyReplay === "immutable_command_result",
    expected.kind + " metadata live-authority or replay metadata drifted",
  );
  exact(
    authorization?.scopes,
    ["own", "assigned", "operator_team", "tenant"],
    expected.kind + " metadata scopes drifted",
  );
  exact(
    authorization?.principalTypes,
    ["human"],
    expected.kind + " metadata principal types drifted",
  );
  exact(
    authorization?.actorKinds,
    ["operator"],
    expected.kind + " metadata actor kinds drifted",
  );
  exact(
    Object.keys(operation.responses ?? {}),
    ["200", "400", "401", "403", "404", "409", "412", "428", "503"],
    expected.kind + " metadata outcome set drifted",
  );
  const success = operation.responses["200"];
  assert(
    success.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      success.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
      success.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/" + expected.kind + "Metadata",
    expected.kind + " metadata success projection or headers drifted",
  );
  for (const status of [
    "400",
    "401",
    "403",
    "404",
    "409",
    "412",
    "428",
    "503",
  ]) {
    assert(
      operation.responses[status]?.$ref?.startsWith(
        "#/components/responses/NoStore",
      ) === true,
      expected.kind + " metadata " + status + " must remain no-store",
    );
  }
}

const baseFields = [
  "title",
  "description",
  "severity",
  "priority",
  "category",
  "classification",
  "customerVisible",
  "tags",
];
for (const kind of ["Alert", "Case"]) {
  const request = schemas[kind + "MetadataReplaceRequest"];
  const response = schemas[kind + "Metadata"];
  const fields =
    kind === "Case" ? ["title", "summary", ...baseFields.slice(1)] : baseFields;
  exact(request.required, fields, kind + " metadata request allowlist drifted");
  exact(
    response.required,
    ["id", ...fields, "version", "updatedAt"],
    kind + " metadata response allowlist drifted",
  );
  assert(
    request.additionalProperties === false &&
      response.additionalProperties === false,
    kind + " metadata schemas must reject unknown properties",
  );
  exact(
    Object.keys(request.properties),
    fields,
    kind + " metadata request property set drifted",
  );
  exact(
    Object.keys(response.properties),
    ["id", ...fields, "version", "updatedAt"],
    kind + " metadata response property set drifted",
  );
  for (const field of ["title", "category", "classification"]) {
    assert(
      request.properties[field].pattern === singleLinePattern &&
        response.properties[field].pattern === singleLinePattern,
      kind + " " + field + " must use the canonical single-line pattern",
    );
  }
  const multilineFields =
    kind === "Case" ? ["summary", "description"] : ["description"];
  for (const field of multilineFields) {
    assert(
      request.properties[field].pattern === multilinePattern &&
        response.properties[field].pattern === multilinePattern,
      kind + " " + field + " must use the canonical multiline pattern",
    );
  }
  assert(
    [request, response].every(
      (schema) =>
        schema.properties.title.minLength === 1 &&
        schema.properties.title.maxLength === 240 &&
        schema.properties.category.minLength === 1 &&
        schema.properties.category.maxLength === 120 &&
        schema.properties.classification.minLength === 1 &&
        schema.properties.classification.maxLength === 120 &&
        schema.properties.severity.$ref ===
          "#/components/schemas/AlertSeverity" &&
        schema.properties.priority.$ref ===
          "#/components/schemas/TicketPriority" &&
        schema.properties.customerVisible.type === "boolean" &&
        schema.properties.tags.$ref === "#/components/schemas/TicketTags",
    ),
    kind + " single-line limits drifted",
  );
  const descriptionLimit = kind === "Alert" ? 10_000 : 20_000;
  assert(
    request.properties.description.maxLength === descriptionLimit &&
      response.properties.description.maxLength === descriptionLimit,
    kind + " description limit drifted",
  );
  if (kind === "Case") {
    assert(
      request.properties.summary.maxLength === 2_000 &&
        response.properties.summary.maxLength === 2_000,
      "Case summary limit drifted",
    );
  } else {
    assert(
      request.properties.summary === undefined &&
        response.properties.summary === undefined,
      "Alert metadata must structurally exclude summary",
    );
  }
  exact(
    request.properties.classification.type,
    ["string", "null"],
    kind + " classification must remain explicit and nullable",
  );
  exact(
    response.properties.classification.type,
    ["string", "null"],
    kind + " response classification must remain explicit and nullable",
  );
  assert(
    response.properties.id.type === "string" &&
      response.properties.id.format === "uuid" &&
      response.properties.version.$ref ===
        "#/components/schemas/ResourceVersion" &&
      response.properties.updatedAt.type === "string" &&
      response.properties.updatedAt.format === "date-time",
    kind + " response identity, version, or timestamp drifted",
  );
}

assert(
  schemas.ResourceVersion.minimum === 1 &&
    schemas.ResourceVersion.maximum === 2_147_483_647 &&
    document.components.parameters.MetadataIfMatch.schema.$ref ===
      "#/components/schemas/MetadataStrongEntityTag" &&
    schemas.MetadataStrongEntityTag.minLength === 4 &&
    schemas.MetadataStrongEntityTag.maxLength === 13 &&
    schemas.MetadataStrongEntityTag.pattern ===
      '^"v(?:[1-9][0-9]{0,8}|1[0-9]{9}|20[0-9]{8}|21[0-3][0-9]{7}|214[0-6][0-9]{6}|2147[0-3][0-9]{5}|21474[0-7][0-9]{4}|214748[0-2][0-9]{3}|2147483[0-5][0-9]{2}|21474836[0-3][0-9]|214748364[0-6])"(?![\\s\\S])',
  "metadata CAS bounds drifted",
);
const metadataEtag = new RegExp(schemas.MetadataStrongEntityTag.pattern, "u");
for (const accepted of ['"v1"', '"v2147483646"']) {
  assert(metadataEtag.test(accepted), "metadata ETag rejected " + accepted);
}
for (const rejected of ['"v0"', '"v01"', '"v2147483647"', 'W/"v1"', '"v1"\n']) {
  assert(!metadataEtag.test(rejected), "metadata ETag accepted " + rejected);
}
assert(
  schemas.TicketTags.maxItems === 100 &&
    schemas.TicketTags.uniqueItems === true &&
    schemas.TicketTags.items.pattern === "^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$" &&
    schemas.TicketTags.description.includes("Unicode code point"),
  "metadata tag grammar, uniqueness, bounds, or ordering drifted",
);

for (const value of [
  "Response plan",
  "\uFEFFvalue\uFEFF",
  "internal\u3000space",
]) {
  assert(
    singleLine.test(value),
    "single-line pattern rejected " + JSON.stringify(value),
  );
}
for (const codePoint of [
  ...Array.from({ length: 0x20 }, (_, index) => index),
  ...Array.from({ length: 0x21 }, (_, index) => 0x7f + index),
]) {
  const control = String.fromCodePoint(codePoint);
  assert(
    !singleLine.test("before" + control + "after"),
    "single-line pattern accepted control U+" +
      codePoint.toString(16).padStart(4, "0"),
  );
  const multilineAllows = [0x09, 0x0a, 0x0d].includes(codePoint);
  assert(
    multiline.test("before" + control + "after") === multilineAllows,
    "multiline control parity drifted for U+" +
      codePoint.toString(16).padStart(4, "0"),
  );
}
for (const value of [
  "",
  "first\tsecond\nthird\rfourth",
  "\uFEFFvalue\uFEFF",
  "internal\u2028separator",
]) {
  assert(
    multiline.test(value),
    "multiline pattern rejected " + JSON.stringify(value),
  );
}
for (const whitespace of [
  "\u0009",
  "\u000A",
  "\u000B",
  "\u000C",
  "\u000D",
  "\u0020",
  "\u0085",
  "\u00A0",
  "\u1680",
  "\u2000",
  "\u2001",
  "\u2002",
  "\u2003",
  "\u2004",
  "\u2005",
  "\u2006",
  "\u2007",
  "\u2008",
  "\u2009",
  "\u200A",
  "\u2028",
  "\u2029",
  "\u202F",
  "\u205F",
  "\u3000",
]) {
  assert(
    !singleLine.test(whitespace + "value") &&
      !singleLine.test("value" + whitespace) &&
      !multiline.test(whitespace + "value") &&
      !multiline.test("value" + whitespace),
    "canonical edge whitespace " + JSON.stringify(whitespace) + " was accepted",
  );
}
for (const value of [
  "line\nbreak",
  "value\n",
  "value\r",
  "value\r\n",
  "value\u0000",
  "value\u0085inside",
]) {
  assert(
    !singleLine.test(value),
    "single-line control " + JSON.stringify(value) + " was accepted",
  );
}
for (const value of [
  "first\u0000second",
  "first\u000Bsecond",
  "first\u0085second",
  "value\n",
  "value\r",
  "value\r\n",
]) {
  assert(
    !multiline.test(value),
    "multiline control " + JSON.stringify(value) + " was accepted",
  );
}

for (const operation of operations) {
  assert(
    generatedSdk.includes("export const " + operation.operationId + " ="),
    "generated TypeScript SDK is missing " + operation.operationId,
  );
  for (const symbol of [
    operation.kind + "MetadataReplaceRequest",
    operation.kind + "Metadata",
    "ReplaceTenant" + operation.kind + "MetadataData",
  ]) {
    assert(
      generatedTypes.includes("export type " + symbol + " ="),
      "generated TypeScript types are missing " + symbol,
    );
  }
}
assert(
  generatedTypes.includes("export type MetadataStrongEntityTag ="),
  "generated TypeScript types are missing MetadataStrongEntityTag",
);

process.stdout.write("Ticket-metadata contract invariants verified.\n");
