import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);

const fail = (message) => {
  throw new Error(
    `Workflow administration contract invariant failed: ${message}`,
  );
};
const assert = (condition, message) => {
  if (!condition) fail(message);
};
const exact = (actual, expected, message) => {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: received ${JSON.stringify(actual)}`,
  );
};
const operation = (path, method) => {
  const value = document.paths?.[path]?.[method];
  assert(value !== undefined, `${method.toUpperCase()} ${path} is missing`);
  return value;
};
const parameterRefs = (value) =>
  new Set((value.parameters ?? []).map((parameter) => parameter.$ref));
const requestSchemaRef = (value) =>
  value.requestBody?.content?.["application/json"]?.schema?.$ref;
const responseSchemaRef = (value, status) =>
  value.responses?.[status]?.content?.["application/json"]?.schema?.$ref;
const resolveResponse = (response) => {
  if (response?.$ref === undefined) return response;
  const prefix = "#/components/responses/";
  assert(
    response.$ref.startsWith(prefix),
    `unsupported response ${response.$ref}`,
  );
  const value =
    document.components.responses[response.$ref.slice(prefix.length)];
  assert(value !== undefined, `missing response ${response.$ref}`);
  return value;
};
const schemaRequired = (name, member) =>
  document.components.schemas[name]?.required?.includes(member) === true;

const base = "/api/v1/tenants/{tenantId}/workflows";
const item = `${base}/{workflowId}`;
const versions = `${item}/versions`;
const version = `${versions}/{version}`;

const operations = [
  [base, "get", "listTenantWorkflows", "workflow.read", false, false],
  [base, "post", "createTenantWorkflow", "workflow.manage", true, false],
  [item, "get", "getTenantWorkflow", "workflow.read", false, false],
  [
    item,
    "patch",
    "updateTenantWorkflowMetadata",
    "workflow.manage",
    true,
    true,
  ],
  [
    versions,
    "get",
    "listTenantWorkflowVersions",
    "workflow.read",
    false,
    false,
  ],
  [
    versions,
    "post",
    "publishTenantWorkflowVersion",
    "workflow.manage",
    true,
    true,
  ],
  [version, "get", "getTenantWorkflowVersion", "workflow.read", false, false],
  [
    `${item}/simulate`,
    "post",
    "simulateTenantWorkflow",
    "workflow.read",
    false,
    false,
  ],
  [
    `${item}/default`,
    "post",
    "setDefaultTenantWorkflow",
    "workflow.manage",
    true,
    true,
  ],
  [
    `${item}/archive`,
    "post",
    "archiveTenantWorkflow",
    "workflow.manage",
    true,
    true,
  ],
  [
    `${item}/restore`,
    "post",
    "restoreTenantWorkflow",
    "workflow.manage",
    true,
    true,
  ],
];

for (const [
  path,
  method,
  operationId,
  permission,
  idempotent,
  optimistic,
] of operations) {
  const value = operation(path, method);
  assert(
    value.operationId === operationId,
    `${method.toUpperCase()} ${path} operationId drifted`,
  );
  exact(
    value.security,
    method === "get"
      ? [{ sessionCookie: [] }]
      : [{ sessionCookie: [], csrfToken: [] }],
    `${operationId} authentication must remain an exact live human session boundary`,
  );
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === permission &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} live tenant authorization metadata drifted`,
  );
  exact(authorization.scopes, ["tenant"], `${operationId} scope drifted`);
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} must be human-only`,
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    `${operationId} must reject customer actors`,
  );

  const parameters = parameterRefs(value);
  assert(
    parameters.has("#/components/parameters/IdempotencyKey") === idempotent,
    `${operationId} idempotency requirement drifted`,
  );
  assert(
    parameters.has("#/components/parameters/WorkflowIfMatch") === optimistic,
    `${operationId} workflow precondition requirement drifted`,
  );
  if (optimistic) {
    assert(
      value.responses["412"] !== undefined &&
        value.responses["428"] !== undefined,
      `${operationId} must expose stale and missing preconditions`,
    );
  }
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    const resolved = resolveResponse(response);
    assert(
      resolved.headers?.["Cache-Control"] !== undefined,
      `${operationId} ${status} must be no-store`,
    );
    if (Number(status) < 400) continue;
    assert(
      resolved.content?.["application/problem+json"]?.schema?.$ref ===
        "#/components/schemas/Problem",
      `${operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
}

assert(
  responseSchemaRef(operation(base, "get"), "200") ===
    "#/components/schemas/WorkflowAdminPage" &&
    responseSchemaRef(operation(base, "post"), "201") ===
      "#/components/schemas/WorkflowAdminMutationResult" &&
    responseSchemaRef(operation(item, "get"), "200") ===
      "#/components/schemas/ManagedWorkflow" &&
    responseSchemaRef(operation(versions, "get"), "200") ===
      "#/components/schemas/WorkflowVersionPage" &&
    responseSchemaRef(operation(version, "get"), "200") ===
      "#/components/schemas/WorkflowVersionRecord" &&
    responseSchemaRef(operation(`${item}/simulate`, "post"), "200") ===
      "#/components/schemas/WorkflowSimulationResult",
  "workflow read and mutation projections drifted",
);

exact(
  [
    requestSchemaRef(operation(base, "post")),
    requestSchemaRef(operation(item, "patch")),
    requestSchemaRef(operation(versions, "post")),
    requestSchemaRef(operation(`${item}/simulate`, "post")),
    requestSchemaRef(operation(`${item}/default`, "post")),
  ],
  [
    "#/components/schemas/WorkflowCreateRequest",
    "#/components/schemas/WorkflowMetadataRequest",
    "#/components/schemas/WorkflowPublishRequest",
    "#/components/schemas/WorkflowSimulationRequest",
    "#/components/schemas/WorkflowLifecycleRequest",
  ],
  "workflow request schemas drifted",
);

for (const name of [
  "WorkflowMetadataRequest",
  "WorkflowPublishRequest",
  "WorkflowLifecycleRequest",
]) {
  assert(
    schemaRequired(name, "expectedRevision"),
    `${name} must bind expectedRevision`,
  );
}

const etag = document.components.schemas.WorkflowStrongEntityTag;
assert(
  etag.type === "string" &&
    etag.minLength === 48 &&
    etag.maxLength === 57 &&
    etag.pattern.startsWith('^"v(?:[1-9]') &&
    etag.pattern.includes("214748364[0-7]") &&
    etag.pattern.endsWith('[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]"$'),
  "strong ETag must bind one canonical resource revision and identity digest",
);
assert(
  document.components.parameters.WorkflowIfMatch.required === true &&
    document.components.parameters.WorkflowIfMatch.schema.$ref ===
      "#/components/schemas/WorkflowStrongEntityTag",
  "If-Match must use the workflow-specific strong validator",
);

const effects = document.components.schemas.WorkflowEffectPlan;
exact(
  document.components.schemas.WorkflowEffect.enum,
  ["activity", "audit", "sla", "notification"],
  "workflow effects must remain closed",
);
assert(
  effects.type === "array" &&
    effects.minItems === 2 &&
    effects.maxItems === 4 &&
    effects.uniqueItems === true &&
    effects.minContains === 2 &&
    effects.maxContains === 2 &&
    JSON.stringify(effects.contains?.enum) ===
      JSON.stringify(["activity", "audit"]),
  "activity and audit must remain mandatory workflow effects",
);

const condition = document.components.schemas.WorkflowCondition;
assert(
  condition.oneOf?.length === 4 &&
    condition.discriminator?.propertyName === "kind",
  "workflow conditions must remain a closed typed union",
);
const definition = document.components.schemas.WorkflowDesign;
assert(
  definition.additionalProperties === false &&
    definition.properties.states.minItems === 2 &&
    definition.properties.states.maxItems === 64 &&
    definition.properties.transitions.minItems === 1 &&
    definition.properties.transitions.maxItems === 256,
  "workflow graph bounds drifted",
);
const simulation = document.components.schemas.WorkflowSimulationResult;
assert(
  simulation.properties.explanatory.const === true &&
    simulation.properties.transitions.maxItems === 256 &&
    operation(`${item}/simulate`, "post").summary.includes(
      "without granting authority",
    ),
  "simulation must remain bounded, explanatory, and non-authoritative",
);
