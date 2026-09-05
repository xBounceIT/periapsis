import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const sdk = readFileSync(
  resolve(repositoryRoot, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);
const go = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error(`Audit operations contract invariant failed: ${message}`);
};
const assert = (condition, message) => {
  if (!condition) fail(message);
};

const streamOperations = [
  {
    prefix: "/api/v1/tenants/{tenantId}",
    permission: "audit.export",
    readPermission: "audit.read",
    retentionPermission: "audit.retention.manage",
    scope: "tenant",
    generatedPrefix: "Tenant",
  },
  {
    prefix: "/api/v1/platform",
    permission: "platform.audit.export",
    readPermission: "platform.audit.read",
    retentionPermission: "platform.audit.retention.manage",
    scope: "platform",
    generatedPrefix: "Platform",
  },
];

for (const stream of streamOperations) {
  const exportCollection = document.paths[`${stream.prefix}/audit-exports`];
  const exportItem =
    document.paths[`${stream.prefix}/audit-exports/{exportId}`];
  const cancel =
    document.paths[`${stream.prefix}/audit-exports/{exportId}/cancel`];
  const download =
    document.paths[`${stream.prefix}/audit-exports/{exportId}/download`];
  const retention = document.paths[`${stream.prefix}/audit-retention`];
  const holds = document.paths[`${stream.prefix}/audit-legal-holds`];
  const release =
    document.paths[`${stream.prefix}/audit-legal-holds/{holdId}/release`];

  for (const [name, operation] of [
    ["create", exportCollection?.post],
    ["status", exportItem?.get],
    ["cancel", cancel?.post],
    ["download", download?.get],
  ]) {
    assert(operation, `${stream.scope} ${name} operation is missing`);
    const authorization = operation["x-periapsis-authorization"];
    assert(
      authorization?.permission === stream.permission &&
        authorization.additionalPermissions?.includes(stream.readPermission) &&
        authorization.scopes?.length === 1 &&
        authorization.scopes[0] === stream.scope &&
        authorization.principalTypes?.length === 1 &&
        authorization.principalTypes[0] === "human" &&
        authorization.uiVisibilityIsNotAuthorization === true,
      `${stream.scope} ${name} must preserve deny-by-default export authority`,
    );
  }

  assert(
    exportCollection.post.security?.[0]?.sessionCookie !== undefined &&
      exportCollection.post.security[0].csrfToken !== undefined,
    `${stream.scope} export creation must require the human session/CSRF pair`,
  );
  assert(
    cancel.post.security?.[0]?.sessionCookie !== undefined &&
      cancel.post.security[0].csrfToken !== undefined,
    `${stream.scope} cancellation must require the human session/CSRF pair`,
  );
  assert(
    download.get["x-periapsis-authorization"].liveReauthorization ===
      "every_request",
    `${stream.scope} download must require fresh authorization`,
  );
  assert(
    download.get.responses["200"]?.content?.["application/x-ndjson"] &&
      !download.get.responses["302"] &&
      !download.get.responses["307"],
    `${stream.scope} download must proxy JSONL without a redirect`,
  );

  for (const [name, operation] of [
    ["read retention", retention?.get],
    ["change retention", retention?.put],
    ["place legal hold", holds?.post],
    ["release legal hold", release?.post],
  ]) {
    assert(operation, `${stream.scope} ${name} operation is missing`);
    const authorization = operation["x-periapsis-authorization"];
    assert(
      authorization?.permission === stream.retentionPermission &&
        authorization.scopes?.length === 1 &&
        authorization.scopes[0] === stream.scope &&
        authorization.principalTypes?.length === 1 &&
        authorization.principalTypes[0] === "human" &&
        authorization.uiVisibilityIsNotAuthorization === true,
      `${stream.scope} ${name} must preserve retention authority`,
    );
  }

  for (const operation of [retention.put, holds.post, release.post]) {
    assert(
      operation.security?.[0]?.sessionCookie !== undefined &&
        operation.security[0].csrfToken !== undefined,
      `${operation.operationId} must require the human session/CSRF pair`,
    );
    assert(
      operation.parameters?.some(
        (parameter) =>
          parameter.$ref === "#/components/parameters/AuditOperationReason",
      ),
      `${operation.operationId} must bind a mandatory safe reason`,
    );
  }

  const generatedOperations = ["Create", "Get", "Cancel", "Download"].map(
    (verb) => `${verb}${stream.generatedPrefix}AuditExport`,
  );
  generatedOperations.push(
    `Get${stream.generatedPrefix}AuditRetention`,
    `Update${stream.generatedPrefix}AuditRetention`,
    `Place${stream.generatedPrefix}AuditLegalHold`,
    `Release${stream.generatedPrefix}AuditLegalHold`,
  );
  for (const generatedOperation of generatedOperations) {
    const sdkName = `${generatedOperation[0].toLowerCase()}${generatedOperation.slice(1)}`;
    assert(
      sdk.includes(`export const ${sdkName} =`),
      `${generatedOperation} is missing from the generated TypeScript SDK`,
    );
    assert(
      go.includes(generatedOperation),
      `${generatedOperation} is missing from the generated Go contract`,
    );
  }
}

const exportJob = document.components.schemas.AuditExportJob;
assert(
  exportJob.additionalProperties === false,
  "export jobs must be closed projections",
);
for (const forbidden of [
  "objectKey",
  "downloadUrl",
  "storageUrl",
  "bucket",
  "requesterSessionId",
  "requesterMembershipId",
  "requesterPermissionEpoch",
]) {
  assert(
    exportJob.properties[forbidden] === undefined,
    `export job leaked internal field ${forbidden}`,
  );
}
assert(
  document.components.schemas.AuditExportArtifact?.additionalProperties ===
    false &&
    document.components.schemas.AuditExportArtifact.properties.downloadUrl ===
      undefined &&
    document.components.schemas.AuditExportArtifact.properties.objectKey ===
      undefined,
  "artifact projection must not expose a raw storage locator",
);

const verification = document.components.schemas.AuditChainVerification;
assert(
  verification.required.includes("retainedThroughSequence") &&
    verification.properties.retainedThroughSequence.minimum === 0,
  "chain verification must expose the protected retention prefix anchor",
);

for (const parameterName of ["AuditExportId", "AuditLegalHoldId"]) {
  const parameter = document.components.parameters[parameterName];
  assert(
    parameter.required === true && parameter.schema?.format === "uuid",
    `${parameterName} must remain an explicit required UUID`,
  );
}
const reason = document.components.parameters.AuditOperationReason;
assert(
  reason.required === true &&
    reason.schema?.minLength === 1 &&
    reason.schema?.maxLength === 500 &&
    reason.schema?.pattern ===
      "^[\\x21-\\x2B\\x2D-\\x7E]([\\x20-\\x2B\\x2D-\\x7E]*[\\x21-\\x2B\\x2D-\\x7E])?$",
  "audit operations must bind a mandatory bounded safe reason",
);

console.log("Audit export and retention contract invariants verified.");
