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
  throw new Error(`DFIR contract invariant failed: ${message}`);
};

const assert = (condition, message) => {
  if (!condition) fail(message);
};

const upload = document.components?.schemas?.DfirAttachmentUploadRequest;
assert(upload?.additionalProperties === false, "upload request must be closed");
assert(
  upload.required?.includes("sizeBytes"),
  "upload request must require exact sizeBytes",
);
assert(
  !upload.required?.includes("maximumBytes") &&
    upload.properties?.maximumBytes === undefined,
  "legacy maximumBytes must not remain accepted",
);
assert(
  upload.properties?.sizeBytes?.type === "integer" &&
    upload.properties.sizeBytes.format === "int64" &&
    upload.properties.sizeBytes.minimum === 1 &&
    upload.properties.sizeBytes.maximum === 5_000_000_000,
  "sizeBytes must retain the conservative single-PUT bound",
);

const operation =
  document.paths?.[
    "/api/v1/tenants/{tenantId}/cases/{caseId}/dfir/attachments/prepare-upload"
  ]?.post;
assert(
  operation?.requestBody?.content?.["application/json"]?.schema?.$ref ===
    "#/components/schemas/DfirAttachmentUploadRequest",
  "prepare-upload must consume the exact-size request",
);
assert(
  operation?.responses?.["201"]?.headers?.["Cache-Control"]?.$ref ===
    "#/components/headers/NoStore",
  "prepared upload capabilities must be no-store",
);

const alertBase = "/api/v1/tenants/{tenantId}/alerts/{alertId}/dfir";
const alertWorkspace = document.paths?.[alertBase]?.get;
assert(
  alertWorkspace?.operationId === "getTenantAlertDfirWorkspace" &&
    alertWorkspace.responses?.["200"]?.content?.["application/json"]?.schema
      ?.$ref === "#/components/schemas/DfirAlertWorkspace" &&
    alertWorkspace.responses["200"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore",
  "Alert workspace must use its bounded no-store projection",
);
assert(
  alertWorkspace?.["x-periapsis-authorization"]?.permission ===
    "dfir.ioc.read" &&
    JSON.stringify(
      [
        ...(alertWorkspace["x-periapsis-authorization"].additionalPermissions ??
          []),
      ].sort(),
    ) ===
      JSON.stringify(
        [
          "dfir.asset.read",
          "dfir.timeline.read",
          "dfir.attachment.read",
          "dfir.evidence.read",
          "dfir.task.read",
          "dfir.relationship.read",
        ].sort(),
      ),
  "Alert workspace must declare every live resource-family permission",
);

for (const [suffix, method, operationId, permission, requestRef, cas] of [
  [
    "/iocs",
    "post",
    "createTenantAlertDfirIndicator",
    "dfir.ioc.manage",
    "#/components/schemas/DfirIndicatorCreateRequest",
  ],
  [
    "/iocs/{indicatorId}",
    "put",
    "replaceTenantAlertDfirIndicator",
    "dfir.ioc.manage",
    "#/components/schemas/DfirIndicatorReplaceRequest",
    true,
  ],
  [
    "/assets",
    "post",
    "createTenantAlertDfirAsset",
    "dfir.asset.manage",
    "#/components/schemas/DfirAssetCreateRequest",
  ],
  [
    "/assets/{assetId}",
    "put",
    "replaceTenantAlertDfirAsset",
    "dfir.asset.manage",
    "#/components/schemas/DfirAssetReplaceRequest",
    true,
  ],
  [
    "/timeline-events",
    "post",
    "createTenantAlertDfirTimelineEvent",
    "dfir.timeline.manage",
    "#/components/schemas/DfirAlertTimelineEventCreateRequest",
  ],
  [
    "/attachments/prepare-upload",
    "post",
    "prepareTenantAlertDfirAttachmentUpload",
    "dfir.attachment.manage",
    "#/components/schemas/DfirAttachmentUploadRequest",
  ],
  [
    "/evidence",
    "post",
    "collectTenantAlertDfirEvidence",
    "dfir.evidence.manage",
    "#/components/schemas/DfirAlertEvidenceCollectRequest",
  ],
  [
    "/evidence/{evidenceId}/custody",
    "post",
    "appendTenantAlertDfirCustodyEvent",
    "dfir.evidence.manage",
    "#/components/schemas/DfirAlertCustodyAppendRequest",
    true,
  ],
  [
    "/tasks",
    "post",
    "createTenantAlertDfirTask",
    "dfir.task.manage",
    "#/components/schemas/DfirAlertTaskCreateRequest",
  ],
  [
    "/tasks/{taskId}/transition",
    "post",
    "transitionTenantAlertDfirTask",
    "dfir.task.manage",
    "#/components/schemas/DfirAlertTaskTransitionRequest",
    true,
  ],
  [
    "/tasks/{taskId}/details",
    "put",
    "replaceTenantAlertDfirTaskDetails",
    "dfir.task.manage",
    "#/components/schemas/DfirTaskDetailsRequest",
    true,
  ],
  [
    "/tasks/{taskId}/assignment",
    "put",
    "assignTenantAlertDfirTask",
    "dfir.task.manage",
    "#/components/schemas/DfirAlertTaskAssignmentRequest",
    true,
  ],
  [
    "/tasks/{taskId}/due-date",
    "put",
    "rescheduleTenantAlertDfirTask",
    "dfir.task.manage",
    "#/components/schemas/DfirAlertTaskDueDateRequest",
    true,
  ],
  [
    "/tasks/{taskId}/checklist",
    "put",
    "replaceTenantAlertDfirTaskChecklist",
    "dfir.task.manage",
    "#/components/schemas/DfirAlertTaskChecklistRequest",
    true,
  ],
  [
    "/tasks/{taskId}/comments",
    "put",
    "replaceTenantAlertDfirTaskComments",
    "dfir.task.manage",
    "#/components/schemas/DfirTaskCommentsRequest",
    true,
  ],
  [
    "/relationships",
    "post",
    "createTenantAlertDfirRelationship",
    "dfir.relationship.manage",
    "#/components/schemas/DfirAlertRelationshipCreateRequest",
  ],
  [
    "/relationships/{relationshipId}/retract",
    "post",
    "retractTenantAlertDfirRelationship",
    "dfir.relationship.manage",
    "#/components/schemas/DfirAlertRelationshipRetractRequest",
    true,
  ],
]) {
  const alertOperation = document.paths?.[`${alertBase}${suffix}`]?.[method];
  const parameterRefs = new Set(
    (alertOperation?.parameters ?? []).map((parameter) => parameter.$ref),
  );
  assert(
    alertOperation?.operationId === operationId &&
      alertOperation["x-periapsis-authorization"]?.permission === permission &&
      alertOperation.requestBody?.content?.["application/json"]?.schema
        ?.$ref === requestRef &&
      parameterRefs.has("#/components/parameters/IdempotencyKey") &&
      (!cas ||
        parameterRefs.has("#/components/parameters/DfirResourceIfMatch")),
    `${method.toUpperCase()} ${suffix} must remain permission-, idempotency-, and contract-bound`,
  );
}

for (const [suffix, method, status, responseRef, created] of [
  [
    "/evidence",
    "post",
    "201",
    "#/components/responses/DfirAlertEvidenceCreated",
    true,
  ],
  [
    "/evidence/{evidenceId}/custody",
    "post",
    "200",
    "#/components/responses/DfirAlertEvidenceUpdated",
  ],
  [
    "/tasks",
    "post",
    "201",
    "#/components/responses/DfirAlertTaskCreated",
    true,
  ],
  [
    "/tasks/{taskId}/transition",
    "post",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/tasks/{taskId}/details",
    "put",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/tasks/{taskId}/assignment",
    "put",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/tasks/{taskId}/due-date",
    "put",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/tasks/{taskId}/checklist",
    "put",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/tasks/{taskId}/comments",
    "put",
    "200",
    "#/components/responses/DfirAlertTaskUpdated",
  ],
  [
    "/relationships",
    "post",
    "201",
    "#/components/responses/DfirAlertRelationshipCreated",
    true,
  ],
  [
    "/relationships/{relationshipId}/retract",
    "post",
    "200",
    "#/components/responses/DfirAlertRelationshipUpdated",
  ],
]) {
  const operation = document.paths?.[`${alertBase}${suffix}`]?.[method];
  const response = operation?.responses?.[status];
  const responseName = responseRef.slice("#/components/responses/".length);
  const component = document.components?.responses?.[responseName];
  assert(
    response?.$ref === responseRef &&
      component?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
      component.headers?.ETag?.$ref ===
        "#/components/headers/DfirResourceStrongETag" &&
      component.headers?.["X-Idempotent-Replay"]?.$ref ===
        "#/components/headers/IdempotentReplay" &&
      (!created ||
        component.headers?.Location?.$ref ===
          "#/components/headers/ResourceLocation"),
    `${method.toUpperCase()} ${suffix} must expose no-store, strong version, and immutable replay headers`,
  );
}

const alertDownload =
  document.paths?.[`${alertBase}/attachments/{attachmentId}/prepare-download`]
    ?.post;
assert(
  alertDownload?.operationId === "prepareTenantAlertDfirAttachmentDownload" &&
    alertDownload["x-periapsis-authorization"]?.permission ===
      "dfir.attachment.read" &&
    alertDownload.requestBody?.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/DfirAttachmentDownloadRequest" &&
    alertDownload.responses?.["200"]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore",
  "Alert attachment download must reauthorize the exact subject and remain no-store",
);

for (const schemaName of [
  "DfirAlertIndicator",
  "DfirAlertAsset",
  "DfirAlertTimelineEvent",
  "DfirAlertEvidence",
  "DfirAlertTask",
  "DfirAlertRelationship",
]) {
  const schema = document.components?.schemas?.[schemaName];
  assert(
    schema?.additionalProperties === false &&
      schema.required?.includes("alertId") &&
      schema.properties?.alertId?.format === "uuid" &&
      schema.properties?.caseId === undefined,
    `${schemaName} must be bound only to the autonomous Alert`,
  );
}
assert(
  document.components?.schemas?.DfirAlertTimelineEventSpec?.properties
    ?.evidenceIds?.maxItems === 256 &&
    document.components.schemas.DfirAlertTimelineEventSpec.properties.evidenceIds.description?.includes(
      "same Alert",
    ),
  "Alert timeline evidence links must stay bounded and exact-rooted",
);
assert(
  document.components?.schemas?.DfirAlertWorkspace?.properties?.indicators
    ?.maxItems === 500 &&
    document.components.schemas.DfirAlertWorkspace.properties.assets
      .maxItems === 500 &&
    document.components.schemas.DfirAlertWorkspace.properties.timeline
      .maxItems === 1000 &&
    document.components.schemas.DfirAlertWorkspace.properties.attachments
      .maxItems === 500 &&
    document.components.schemas.DfirAlertWorkspace.properties.evidence
      .maxItems === 500 &&
    document.components.schemas.DfirAlertWorkspace.properties.tasks.maxItems ===
      500 &&
    document.components.schemas.DfirAlertWorkspace.properties.relationships
      .maxItems === 1000,
  "Alert workspace resource families must remain bounded",
);

const caseTaskBase = "/api/v1/tenants/{tenantId}/cases/{caseId}/dfir/tasks";
for (const [suffix, method, operationId, requestRef, cas] of [
  ["", "post", "createTenantCaseDfirTask", "DfirTaskCreateRequest", false],
  [
    "/{taskId}/transition",
    "post",
    "transitionTenantCaseDfirTask",
    "DfirTaskTransitionRequest",
    true,
  ],
  [
    "/{taskId}/details",
    "put",
    "replaceTenantCaseDfirTaskDetails",
    "DfirTaskDetailsRequest",
    true,
  ],
  [
    "/{taskId}/assignment",
    "put",
    "assignTenantCaseDfirTask",
    "DfirTaskAssignmentRequest",
    true,
  ],
  [
    "/{taskId}/due-date",
    "put",
    "rescheduleTenantCaseDfirTask",
    "DfirTaskDueDateRequest",
    true,
  ],
  [
    "/{taskId}/checklist",
    "put",
    "replaceTenantCaseDfirTaskChecklist",
    "DfirTaskChecklistRequest",
    true,
  ],
  [
    "/{taskId}/comments",
    "put",
    "replaceTenantCaseDfirTaskComments",
    "DfirTaskCommentsRequest",
    true,
  ],
]) {
  const caseTaskOperation =
    document.paths?.[`${caseTaskBase}${suffix}`]?.[method];
  const parameterRefs = new Set(
    (caseTaskOperation?.parameters ?? []).map((parameter) => parameter.$ref),
  );
  assert(
    caseTaskOperation?.operationId === operationId &&
      caseTaskOperation["x-periapsis-authorization"]?.permission ===
        "dfir.task.manage" &&
      JSON.stringify(caseTaskOperation["x-periapsis-authorization"]?.scopes) ===
        JSON.stringify(["assigned", "operator_team", "tenant"]) &&
      caseTaskOperation.requestBody?.content?.["application/json"]?.schema
        ?.$ref === `#/components/schemas/${requestRef}` &&
      parameterRefs.has("#/components/parameters/IdempotencyKey") &&
      (!cas ||
        parameterRefs.has("#/components/parameters/DfirResourceIfMatch")),
    `${method.toUpperCase()} Case task ${suffix || "create"} must remain exact-root, fail-closed, idempotent, and CAS-bound`,
  );
}

const taskSpec = document.components?.schemas?.DfirTaskSpec;
const taskSpecFields = Object.keys(taskSpec?.properties ?? {}).sort();
assert(
  taskSpec?.additionalProperties === false &&
    JSON.stringify(taskSpecFields) ===
      JSON.stringify(
        [
          "assigneeId",
          "checklist",
          "description",
          "dueAt",
          "operatorTeamId",
          "priority",
          "slaInstanceId",
          "title",
        ].sort(),
      ) &&
    ![
      "status",
      "completedAt",
      "completedBy",
      "completionData",
      "commentIds",
      "version",
    ].some((field) => taskSpec?.properties?.[field] !== undefined),
  "Case task create must expose intent only and keep lifecycle/provenance/comments server-owned",
);
const checklistIntent =
  document.components?.schemas?.DfirTaskChecklistItemIntent;
assert(
  checklistIntent?.additionalProperties === false &&
    JSON.stringify(Object.keys(checklistIntent.properties ?? {}).sort()) ===
      JSON.stringify(["completed", "id", "title"]) &&
    checklistIntent.required?.includes("completed") &&
    checklistIntent.properties?.completedAt === undefined &&
    checklistIntent.properties?.completedBy === undefined,
  "Case task checklist writes must not accept forged completion provenance",
);
assert(
  document.components?.schemas?.DfirResourceVersion?.format === "int64" &&
    document.components.schemas.DfirResourceVersion.minimum === 1 &&
    document.components.schemas.DfirResourceVersion.maximum ===
      9_007_199_254_740_991 &&
    document.components.schemas.DfirExpectedResourceVersion?.format ===
      "int64" &&
    document.components.schemas.DfirExpectedResourceVersion.minimum === 1 &&
    document.components.schemas.DfirExpectedResourceVersion.maximum ===
      9_007_199_254_740_990 &&
    document.components?.parameters?.DfirResourceIfMatch?.schema?.$ref ===
      "#/components/schemas/DfirResourceStrongEntityTag" &&
    document.components?.headers?.DfirResourceStrongETag?.schema?.$ref ===
      "#/components/schemas/DfirResourceStrongEntityTag",
  "DFIR revisions must use the dedicated bigint-backed JSON-safe CAS boundary",
);
for (const name of [
  "DfirTaskTransitionRequest",
  "DfirTaskDetailsRequest",
  "DfirTaskAssignmentRequest",
  "DfirTaskDueDateRequest",
  "DfirTaskChecklistRequest",
  "DfirTaskCommentsRequest",
]) {
  const schema = document.components?.schemas?.[name];
  assert(
    schema?.additionalProperties === false &&
      schema.required?.includes("expectedVersion") &&
      schema.properties?.expectedVersion?.$ref ===
        "#/components/schemas/DfirExpectedResourceVersion",
    `${name} must be closed and use the exact Task revision boundary`,
  );
}
assert(
  document.components?.schemas?.DfirTaskDetailsRequest?.required?.includes(
    "title",
  ) &&
    document.components.schemas.DfirTaskDetailsRequest.required.includes(
      "description",
    ) &&
    document.components.schemas.DfirTaskDetailsRequest.required.includes(
      "priority",
    ) &&
    !document.components.schemas.DfirTaskDetailsRequest.required.includes(
      "slaInstanceId",
    ),
  "Case task detail replacement must require core fields and use omission to clear SLA",
);

for (const [suffix, method, status, created] of [
  ["", "post", "201", true],
  ["/{taskId}/transition", "post", "200", false],
  ["/{taskId}/details", "put", "200", false],
  ["/{taskId}/assignment", "put", "200", false],
  ["/{taskId}/due-date", "put", "200", false],
  ["/{taskId}/checklist", "put", "200", false],
  ["/{taskId}/comments", "put", "200", false],
]) {
  const operation = document.paths?.[`${caseTaskBase}${suffix}`]?.[method];
  const expectedRef = created
    ? "#/components/responses/DfirTaskCreated"
    : "#/components/responses/DfirTaskUpdated";
  const response = operation?.responses?.[status];
  const component =
    document.components?.responses?.[
      expectedRef.slice("#/components/responses/".length)
    ];
  assert(
    response?.$ref === expectedRef &&
      component?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
      component.headers?.ETag?.$ref ===
        "#/components/headers/DfirResourceStrongETag" &&
      component.headers?.["X-Idempotent-Replay"]?.$ref ===
        "#/components/headers/IdempotentReplay" &&
      (!created ||
        component.headers?.Location?.$ref ===
          "#/components/headers/ResourceLocation"),
    `Case task ${suffix || "create"} response must expose no-store, ETag, and exact replay state`,
  );
}

for (const schemaName of [
  "DfirIndicator",
  "DfirAlertIndicator",
  "DfirAsset",
  "DfirAlertAsset",
  "DfirTimelineEvent",
  "DfirAlertTimelineEvent",
  "DfirTask",
  "DfirAlertTask",
  "DfirRelationship",
  "DfirAlertRelationship",
]) {
  assert(
    document.components?.schemas?.[schemaName]?.properties?.version?.$ref ===
      "#/components/schemas/DfirResourceVersion",
    `${schemaName} snapshot must expose the JSON-safe DFIR revision`,
  );
}

for (const schemaName of [
  "DfirIndicatorReplaceRequest",
  "DfirAssetReplaceRequest",
  "DfirSharedResourceLinkRequest",
  "DfirSharedResourceUnlinkRequest",
  "DfirTaskTransitionRequest",
  "DfirTaskDetailsRequest",
  "DfirTaskAssignmentRequest",
  "DfirTaskDueDateRequest",
  "DfirTaskChecklistRequest",
  "DfirAlertTaskTransitionRequest",
  "DfirAlertTaskAssignmentRequest",
  "DfirAlertTaskDueDateRequest",
  "DfirAlertTaskChecklistRequest",
  "DfirTaskCommentsRequest",
  "DfirRelationshipRetractRequest",
  "DfirAlertRelationshipRetractRequest",
]) {
  assert(
    document.components?.schemas?.[schemaName]?.properties?.expectedVersion
      ?.$ref === "#/components/schemas/DfirExpectedResourceVersion",
    `${schemaName} must pin an incrementable JSON-safe DFIR revision`,
  );
}

const taskComments = document.components?.schemas?.DfirTaskCommentsRequest;
assert(
  taskComments?.additionalProperties === false &&
    JSON.stringify(taskComments.required?.slice().sort()) ===
      JSON.stringify(["commentIds", "expectedVersion"]) &&
    taskComments.properties?.expectedVersion?.$ref ===
      "#/components/schemas/DfirExpectedResourceVersion" &&
    taskComments.properties?.commentIds?.type === "array" &&
    taskComments.properties.commentIds.uniqueItems === true &&
    taskComments.properties.commentIds.maxItems === 1000 &&
    taskComments.properties.commentIds.items?.type === "string" &&
    taskComments.properties.commentIds.items?.format === "uuid",
  "task comment replacement must be closed, full-replace, unique, and bounded to 1000 UUID references",
);

const caseRelationshipBase =
  "/api/v1/tenants/{tenantId}/cases/{caseId}/dfir/relationships";
const caseRelationshipRetraction =
  document.paths?.[`${caseRelationshipBase}/{relationshipId}/retract`]?.post;
const caseRelationshipRetractionParameterRefs = new Set(
  (caseRelationshipRetraction?.parameters ?? []).map(
    (parameter) => parameter.$ref,
  ),
);
assert(
  caseRelationshipRetraction?.operationId ===
    "retractTenantCaseDfirRelationship" &&
    caseRelationshipRetraction["x-periapsis-authorization"]?.permission ===
      "dfir.relationship.manage" &&
    JSON.stringify(
      caseRelationshipRetraction["x-periapsis-authorization"]?.scopes,
    ) === JSON.stringify(["assigned", "operator_team", "tenant"]) &&
    caseRelationshipRetraction.requestBody?.content?.["application/json"]
      ?.schema?.$ref ===
      "#/components/schemas/DfirRelationshipRetractRequest" &&
    caseRelationshipRetractionParameterRefs.has(
      "#/components/parameters/DfirResourceIfMatch",
    ) &&
    caseRelationshipRetractionParameterRefs.has(
      "#/components/parameters/IdempotencyKey",
    ) &&
    caseRelationshipRetraction.responses?.["200"]?.$ref ===
      "#/components/responses/DfirRelationshipUpdated",
  "Case relationship retraction must remain exact-root, permission-, CAS-, idempotency-, and replay-bound",
);

for (const [schemaName, retractionName] of [
  ["DfirRelationship", "DfirRelationshipRetraction"],
  ["DfirAlertRelationship", "DfirAlertRelationshipRetraction"],
]) {
  const schema = document.components?.schemas?.[schemaName];
  assert(
    schema?.required?.includes("active") &&
      schema.required.includes("retractions") &&
      schema.properties?.active?.type === "boolean" &&
      schema.properties?.retractions?.type === "array" &&
      schema.properties.retractions.maxItems === 1 &&
      schema.properties.retractions.items?.$ref ===
        `#/components/schemas/${retractionName}`,
    `${schemaName} must expose real lifecycle state and its bounded immutable retraction history`,
  );
}

const relationshipRetraction =
  document.components?.schemas?.DfirRelationshipRetraction;
assert(
  relationshipRetraction?.additionalProperties === false &&
    JSON.stringify(relationshipRetraction.required?.slice().sort()) ===
      JSON.stringify(
        ["actorId", "id", "occurredAt", "reason", "sequence"].sort(),
      ) &&
    relationshipRetraction.properties?.sequence?.$ref ===
      "#/components/schemas/DfirResourceVersion",
  "relationship retraction history must be closed, attributable, ordered, and JSON-safe",
);

for (const operationId of [
  "replaceTenantCaseDfirTaskComments",
  "replaceTenantAlertDfirTaskComments",
  "retractTenantCaseDfirRelationship",
]) {
  assert(
    generatedSdk.includes(`export const ${operationId} =`),
    `generated TypeScript SDK is missing ${operationId}`,
  );
}
for (const typeName of [
  "DfirTaskCommentsRequest",
  "DfirRelationshipRetractRequest",
  "DfirRelationshipRetraction",
]) {
  assert(
    generatedTypes.includes(`export type ${typeName} =`),
    `generated TypeScript types are missing ${typeName}`,
  );
  assert(
    generatedGo.includes(`type ${typeName} struct {`),
    `generated Go contract is missing ${typeName}`,
  );
}
for (const operationName of [
  "ReplaceTenantCaseDfirTaskComments",
  "ReplaceTenantAlertDfirTaskComments",
  "RetractTenantCaseDfirRelationship",
]) {
  assert(
    generatedGo.includes(`\t${operationName}(w http.ResponseWriter`),
    `generated Go server is missing ${operationName}`,
  );
}

for (const schemaName of [
  "DfirCustodyAppendRequest",
  "DfirAlertCustodyAppendRequest",
]) {
  assert(
    document.components?.schemas?.[schemaName]?.properties?.expectedVersion
      ?.$ref === "#/components/schemas/DfirCustodyExpectedVersion",
    `${schemaName} must stop before the bounded custody snapshot ceiling`,
  );
}

for (const schemaName of ["DfirEvidence", "DfirAlertEvidence"]) {
  assert(
    document.components?.schemas?.[schemaName]?.properties?.version?.$ref ===
      "#/components/schemas/DfirCustodySequence",
    `${schemaName} snapshots must expose a bounded custody revision`,
  );
}
assert(
  document.components?.schemas?.DfirCustodyExpectedVersion?.minimum === 1 &&
    document.components.schemas.DfirCustodyExpectedVersion.maximum === 999 &&
    document.components?.schemas?.DfirCustodySequence?.minimum === 1 &&
    document.components.schemas.DfirCustodySequence.maximum === 1000 &&
    document.components?.schemas?.DfirCustodyEvent?.properties?.sequence
      ?.$ref === "#/components/schemas/DfirCustodySequence",
  "custody request, evidence revision, and event sequence must share the 1000-event ceiling",
);

for (const responseName of [
  "DfirIndicatorCreated",
  "DfirAlertIndicatorCreated",
  "DfirIndicatorUpdated",
  "DfirAlertIndicatorUpdated",
  "DfirAssetCreated",
  "DfirAlertAssetCreated",
  "DfirAssetUpdated",
  "DfirAlertAssetUpdated",
  "DfirTimelineEventCreated",
  "DfirAlertTimelineEventCreated",
  "DfirTaskCreated",
  "DfirTaskUpdated",
  "DfirRelationshipCreated",
  "DfirEvidenceCreated",
  "DfirEvidenceUpdated",
  "DfirAlertEvidenceCreated",
  "DfirAlertEvidenceUpdated",
  "DfirAlertTaskCreated",
  "DfirAlertTaskUpdated",
  "DfirAlertRelationshipCreated",
  "DfirAlertRelationshipUpdated",
]) {
  assert(
    document.components?.responses?.[responseName]?.headers?.ETag?.$ref ===
      "#/components/headers/DfirResourceStrongETag",
    `${responseName} must emit the dedicated DFIR strong ETag`,
  );
}

for (const [root, rootTitle, rootParameter] of [
  ["cases", "Case", "caseId"],
  ["alerts", "Alert", "alertId"],
]) {
  for (const [family, kind, resourceTitle, resourceParameter] of [
    ["iocs", "ioc", "Indicator", "indicatorId"],
    ["assets", "asset", "Asset", "assetId"],
  ]) {
    for (const [action, actionTitle, eventField] of [
      ["link", "Link", "linkId"],
      ["unlink", "Unlink", "unlinkId"],
    ]) {
      const path = `/api/v1/tenants/{tenantId}/${root}/{${rootParameter}}/dfir/${family}/{${resourceParameter}}/${action}`;
      const linkOperation = document.paths?.[path]?.post;
      const schemaName = `DfirSharedResource${actionTitle}Request`;
      const request = document.components?.schemas?.[schemaName];
      const parameters = new Set(
        (linkOperation?.parameters ?? []).map((parameter) => parameter.$ref),
      );
      const operationId = `${action}Tenant${rootTitle}Dfir${resourceTitle}`;
      assert(
        linkOperation?.operationId === operationId &&
          linkOperation["x-periapsis-authorization"]?.permission ===
            `dfir.${kind}.manage` &&
          linkOperation.requestBody?.content?.["application/json"]?.schema
            ?.$ref === `#/components/schemas/${schemaName}` &&
          parameters.has("#/components/parameters/IdempotencyKey") &&
          parameters.has("#/components/parameters/DfirResourceIfMatch") &&
          linkOperation.responses?.["412"] !== undefined &&
          linkOperation.responses?.["428"] !== undefined,
        `${path} must keep its closed CAS/idempotency/manage contract`,
      );
      assert(
        request?.additionalProperties === false &&
          request.required?.includes(eventField) &&
          request.required?.includes("expectedVersion"),
        `${schemaName} must require caller event identity and CAS revision`,
      );
      assert(
        generatedSdk.includes(`export const ${operationId} =`),
        `${operationId} must remain generated from OpenAPI`,
      );
    }
  }
}

process.stdout.write("DFIR contract invariants verified.\n");
