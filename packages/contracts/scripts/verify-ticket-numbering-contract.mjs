import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const contract = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const generatedGo = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);
const generatedTypescript = readFileSync(
  resolve(
    repositoryRoot,
    "packages/contracts/generated/typescript/types.gen.ts",
  ),
  "utf8",
);
const generatedSdk = readFileSync(
  resolve(repositoryRoot, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);

const policyPath =
  contract.paths["/api/v1/tenants/{tenantId}/ticket-numbering/{kind}"];
const previewPath =
  contract.paths["/api/v1/tenants/{tenantId}/ticket-numbering/{kind}/preview"];
assert.ok(policyPath?.get, "ticket-numbering GET operation is missing");
assert.ok(policyPath?.put, "ticket-numbering PUT operation is missing");
assert.ok(previewPath?.post, "ticket-numbering preview operation is missing");

assert.equal(policyPath.get.operationId, "getTenantTicketNumberingPolicy");
assert.equal(policyPath.put.operationId, "updateTenantTicketNumberingPolicy");
assert.equal(
  previewPath.post.operationId,
  "previewTenantTicketNumberingPolicy",
);

assert.deepEqual(policyPath.get.security, [{ sessionCookie: [] }]);
assert.deepEqual(policyPath.put.security, [
  { csrfToken: [], sessionCookie: [] },
]);
assert.deepEqual(previewPath.post.security, [
  { csrfToken: [], sessionCookie: [] },
]);
for (const operation of [policyPath.get, policyPath.put, previewPath.post]) {
  assert.equal(operation["x-periapsis-authorization"].tenantContext, "path");
  assert.equal(operation["x-periapsis-authorization"].activeMembership, true);
  assert.deepEqual(operation["x-periapsis-authorization"].principalTypes, [
    "human",
  ]);
  assert.ok(
    !operation.security.some((entry) => "serviceAccountBearer" in entry),
    `${operation.operationId} must remain browser-session-only`,
  );
}
assert.equal(
  policyPath.get["x-periapsis-authorization"].permission,
  "settings.read",
);
assert.equal(
  previewPath.post["x-periapsis-authorization"].permission,
  "settings.read",
);
assert.deepEqual(policyPath.put["x-periapsis-authorization"].permissions, [
  "settings.read",
  "settings.manage",
]);
assert.equal(
  policyPath.put["x-periapsis-authorization"].idempotencyReplay,
  "immutable_command_result",
);
assert.equal(previewPath.post["x-periapsis-authorization"].sideEffects, "none");

const putParameterRefs = policyPath.put.parameters.map((parameter) =>
  refName(parameter.$ref),
);
assert.deepEqual(putParameterRefs, [
  "IfMatch",
  "IdempotencyKey",
  "TicketNumberingAuditReason",
]);
assert.equal(
  policyPath.put.responses["200"].headers.ETag.$ref,
  "#/components/headers/StrongETag",
);
assert.equal(
  policyPath.put.responses["200"].headers["X-Idempotent-Replay"].$ref,
  "#/components/headers/IdempotentReplay",
);
assert.equal(
  policyPath.get.responses["200"].headers.ETag.$ref,
  "#/components/headers/StrongETag",
);
for (const status of ["409", "412", "428"]) {
  assert.ok(policyPath.put.responses[status], `PUT ${status} is missing`);
}

const schemas = contract.components.schemas;
assert.deepEqual(schemas.TicketNumberingKind.enum, ["alert", "case"]);
assert.deepEqual(schemas.TicketNumberingSeparator.enum, ["-", "/", ".", "_"]);
assert.deepEqual(schemas.TicketNumberingPeriod.enum, ["annual", "lifetime"]);
assertClosedRequired(schemas.TicketNumberingDraft, [
  "prefix",
  "separator",
  "period",
  "width",
  "start",
]);
assert.equal(schemas.TicketNumberingDraft.properties.width.minimum, 4);
assert.equal(schemas.TicketNumberingDraft.properties.width.maximum, 12);
assert.equal(schemas.TicketNumberingDraft.properties.start.minimum, 1);
assert.equal(
  schemas.TicketNumberingDraft.properties.start.maximum,
  999_999_999_999,
);
assert.equal(schemas.TicketNumberingDraft.allOf.length, 9);
assertClosedRequired(schemas.TicketNumberingPolicy, [
  "versionId",
  "tenantId",
  "kind",
  "version",
  "prefix",
  "separator",
  "period",
  "width",
  "start",
  "publisher",
  "publishedAt",
]);
assertClosedRequired(schemas.TicketNumberingPublisher, [
  "type",
  "membershipId",
]);
assert.deepEqual(schemas.TicketNumberingPublisher.properties.type.enum, [
  "system",
  "membership",
]);
assert.deepEqual(
  schemas.TicketNumberingPublisher.properties.membershipId.type,
  ["string", "null"],
);
assert.equal(schemas.TicketNumberingPublisher.allOf.length, 2);
assertClosedRequired(schemas.TicketNumberingUpdateRequest, [
  "expectedVersion",
  "prefix",
  "separator",
  "period",
  "width",
  "start",
]);
assert.equal(
  schemas.TicketNumberingUpdateRequest.properties.expectedVersion.maximum,
  2_147_483_646,
);
assert.equal(schemas.TicketNumberingUpdateRequest.allOf.length, 9);
assertClosedRequired(schemas.TicketNumberingPreview, [
  "tenantId",
  "kind",
  "prefix",
  "separator",
  "period",
  "width",
  "start",
  "maximumSequence",
  "at",
  "periodKey",
  "example",
]);
assert.equal(
  schemas.TicketNumberingPreview.properties.maximumSequence.maximum,
  999_999_999_999,
);
assert.equal(schemas.TicketNumberingPreview.properties.periodKey.minimum, 0);
assert.match(
  schemas.TicketNumberingPreview.properties.at.pattern,
  /Z\$$/u,
  "preview instant must be canonical UTC",
);
assertClosedRequired(schemas.TicketNumberingMutationResult, [
  "policy",
  "replayed",
]);

for (const signature of [
  "GetTenantTicketNumberingPolicy(w http.ResponseWriter",
  "UpdateTenantTicketNumberingPolicy(w http.ResponseWriter",
  "PreviewTenantTicketNumberingPolicy(w http.ResponseWriter",
  "type TicketNumberingPolicy struct",
  "type TicketNumberingPreview struct",
  "type TicketNumberingMutationResult struct",
]) {
  assert.ok(generatedGo.includes(signature), `${signature} is missing from Go`);
}
for (const signature of [
  "export type TicketNumberingPolicy =",
  "export type TicketNumberingPreview =",
  "export type TicketNumberingMutationResult =",
]) {
  assert.ok(
    generatedTypescript.includes(signature),
    `${signature} is missing from TypeScript`,
  );
}
for (const operation of [
  "export const getTenantTicketNumberingPolicy =",
  "export const updateTenantTicketNumberingPolicy =",
  "export const previewTenantTicketNumberingPolicy =",
]) {
  assert.ok(
    generatedSdk.includes(operation),
    `${operation} is missing from SDK`,
  );
}

process.stdout.write("Ticket numbering contract invariants verified.\n");

function assertClosedRequired(schema, required) {
  assert.equal(schema.type, "object");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(schema.required, required);
}

function refName(reference) {
  assert.equal(typeof reference, "string");
  return reference.split("/").at(-1);
}
