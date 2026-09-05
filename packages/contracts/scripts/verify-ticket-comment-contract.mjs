import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(root, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const generatedSdk = readFileSync(
  resolve(root, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);
const generatedTypes = readFileSync(
  resolve(root, "packages/contracts/generated/typescript/types.gen.ts"),
  "utf8",
);
const generatedGo = readFileSync(
  resolve(root, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error(`Ticket-comment contract invariant failed: ${message}`);
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
  value.parameters?.map((parameter) => parameter.$ref) ?? [];
const responseSchema = (value, status) =>
  value.responses?.[status]?.content?.["application/json"]?.schema;
const requestSchema = (value) =>
  value.requestBody?.content?.["application/json"]?.schema;
const scopes = ["own", "assigned", "operator_team", "tenant"];

const operatorKinds = [
  {
    kind: "Alert",
    key: "alert",
    id: "alertId",
    idRef: "#/components/parameters/AlertId",
  },
  {
    kind: "Case",
    key: "case",
    id: "caseId",
    idRef: "#/components/parameters/CaseId",
  },
];

for (const expected of operatorKinds) {
  const base = `/api/v1/tenants/{tenantId}/${expected.key}s/{${expected.id}}/comments`;
  const collection = document.paths[base];
  exact(
    collection.parameters.map((parameter) => parameter.$ref),
    ["#/components/parameters/TenantId", expected.idRef],
    `${expected.kind} comment collection coordinates drifted`,
  );
  assert(
    collection.get["x-periapsis-authorization"].permission ===
      `${expected.key}.comment.read` &&
      collection.get["x-periapsis-authorization"].liveTicketReadPermission ===
        `${expected.key}.read` &&
      collection.get["x-periapsis-authorization"].permissionResolution ===
        "same_live_authority_snapshot" &&
      collection.get["x-periapsis-authorization"].projection ===
        "operator_only" &&
      responseSchema(collection.get, "200")?.$ref ===
        "#/components/schemas/OperatorCommentList",
    `${expected.kind} comment list must require comment.read and remain operator-only`,
  );
  exact(
    parameterRefs(collection.get),
    [
      "#/components/parameters/CommentAfterCursor",
      "#/components/parameters/PageSize",
    ],
    `${expected.kind} comment list cursor drifted`,
  );
  assertNoStore(collection.get);
  assert(
    collection.post.operationId === `createTenant${expected.kind}Comment` &&
      requestSchema(collection.post)?.$ref ===
        "#/components/schemas/CommentCreateRequest" &&
      responseSchema(collection.post, "201")?.$ref ===
        "#/components/schemas/OperatorComment" &&
      collection.post.responses["201"].headers.ETag.$ref ===
        "#/components/headers/CommentStrongETag" &&
      collection.post.responses["201"].headers["X-Idempotent-Replay"].$ref ===
        "#/components/headers/IdempotentReplay" &&
      collection.post.responses["201"].headers["Cache-Control"].$ref ===
        "#/components/headers/NoStore" &&
      collection.post["x-periapsis-authorization"].liveTicketReadPermission ===
        `${expected.key}.read` &&
      collection.post["x-periapsis-authorization"].permissionResolution ===
        "same_live_authority_snapshot",
    `${expected.kind} existing create ABI drifted`,
  );
  assertNoStore(collection.post);

  const preview = operation(`${base}/preview`, "post");
  exact(
    preview.operationId,
    `previewTenant${expected.kind}Comment`,
    `${expected.kind} preview operationId drifted`,
  );
  assert(
    requestSchema(preview)?.$ref ===
      "#/components/schemas/CommentCreateRequest" &&
      responseSchema(preview, "200")?.$ref ===
        "#/components/schemas/OperatorCommentPreview" &&
      preview["x-periapsis-authorization"].liveTicketReadPermission ===
        `${expected.key}.read`,
    `${expected.kind} preview request, response, or live read drifted`,
  );

  const candidates = operation(`${base}/mention-candidates`, "get");
  exact(
    candidates.operationId,
    `listTenant${expected.kind}CommentMentionCandidates`,
    `${expected.kind} candidate operationId drifted`,
  );
  const candidateAuth = candidates["x-periapsis-authorization"];
  assert(
    candidateAuth.nonOracular === true &&
      candidateAuth.ticketScoped === true &&
      candidateAuth.liveTicketReadPermission === `${expected.key}.read`,
    `${expected.kind} candidates must remain non-oracular and ticket-scoped`,
  );
  exact(
    candidateAuth.candidatePrincipalTypes,
    ["human"],
    `${expected.kind} candidates must remain human-only`,
  );
  assert(
    responseSchema(candidates, "200")?.$ref ===
      "#/components/schemas/CommentMentionCandidateList",
    `${expected.kind} candidate projection drifted`,
  );

  const member = `${base}/{commentId}`;
  const edit = operation(member, "patch");
  exact(
    document.paths[member].parameters.map((parameter) => parameter.$ref),
    [
      "#/components/parameters/TenantId",
      expected.idRef,
      "#/components/parameters/CommentId",
    ],
    `${expected.kind} comment member coordinates drifted`,
  );
  exact(
    edit.operationId,
    `editTenant${expected.kind}Comment`,
    `${expected.kind} edit operationId drifted`,
  );
  exact(
    parameterRefs(edit),
    [
      "#/components/parameters/CommentIfMatch",
      "#/components/parameters/IdempotencyKey",
    ],
    `${expected.kind} edit CAS or idempotency drifted`,
  );
  const editAuth = edit["x-periapsis-authorization"];
  assert(
    editAuth.authorOnly === "frozen_membership" &&
      editAuth.editWindowSeconds === 900 &&
      editAuth.visibilityChange === "forbidden" &&
      editAuth.delete === "forbidden" &&
      editAuth.adminOverride === "forbidden" &&
      editAuth.liveTicketReadPermission === `${expected.key}.read` &&
      editAuth.conditionalPermissions?.private ===
        `${expected.key}.comment.private` &&
      JSON.stringify(editAuth.editableOrigins) === JSON.stringify(["api"]),
    `${expected.kind} author-only append semantics drifted`,
  );
  assert(
    requestSchema(edit)?.$ref === "#/components/schemas/CommentEditRequest" &&
      responseSchema(edit, "200")?.$ref ===
        "#/components/schemas/OperatorComment" &&
      edit.responses["200"].headers.ETag.$ref ===
        "#/components/headers/CommentStrongETag" &&
      edit.responses["200"].headers["X-Idempotent-Replay"].$ref ===
        "#/components/headers/IdempotentReplay" &&
      edit.responses["412"] !== undefined &&
      edit.responses["428"] !== undefined,
    `${expected.kind} edit schema, ETag, replay, or CAS outcomes drifted`,
  );
  assertNoStore(edit);

  const history = operation(`${member}/revisions`, "get");
  exact(
    history.operationId,
    `listTenant${expected.kind}CommentRevisions`,
    `${expected.kind} history operationId drifted`,
  );
  assert(
    history["x-periapsis-authorization"].permission ===
      `${expected.key}.comment.read` &&
      responseSchema(history, "200")?.$ref ===
        "#/components/schemas/OperatorCommentRevisionList",
    `${expected.kind} history authority or projection drifted`,
  );
  exact(
    history["x-periapsis-authorization"].scopes,
    scopes,
    `${expected.kind} history scopes drifted`,
  );
  for (const authorityBoundOperation of [preview, candidates, edit, history]) {
    assert(
      authorityBoundOperation["x-periapsis-authorization"]
        .permissionResolution === "same_live_authority_snapshot",
      `${authorityBoundOperation.operationId} must resolve permissions from one live snapshot`,
    );
  }
  assertNoStore(preview);
  assertNoStore(candidates);
  assertNoStore(history);
}

for (const expected of operatorKinds) {
  const base = `/api/v1/tenants/{tenantId}/portal/${expected.key}s/{${expected.id}}/comments`;
  const create = operation(base, "post");
  const list = operation(base, "get");
  const preview = operation(`${base}/preview`, "post");
  const edit = operation(`${base}/{commentId}`, "patch");
  const history = operation(`${base}/{commentId}/revisions`, "get");
  exact(
    parameterRefs(list),
    [
      "#/components/parameters/CommentAfterCursor",
      "#/components/parameters/PageSize",
    ],
    `${expected.kind} portal comment list cursor drifted`,
  );
  exact(
    preview.operationId,
    `previewCustomerPortal${expected.kind}Comment`,
    `${expected.kind} portal preview operationId drifted`,
  );
  assert(
    create.responses["201"].headers.ETag.$ref ===
      "#/components/headers/CommentStrongETag" &&
      create.responses["201"].headers["X-Idempotent-Replay"].$ref ===
        "#/components/headers/IdempotentReplay" &&
      create.responses["201"].headers["Cache-Control"].$ref ===
        "#/components/headers/NoStore",
    `${expected.kind} portal create receipt drifted`,
  );
  exact(
    edit.operationId,
    `editCustomerPortal${expected.kind}Comment`,
    `${expected.kind} portal edit operationId drifted`,
  );
  exact(
    history.operationId,
    `listCustomerPortal${expected.kind}CommentRevisions`,
    `${expected.kind} portal history operationId drifted`,
  );
  assert(
    requestSchema(preview)?.$ref ===
      "#/components/schemas/CustomerPortalCommentPreviewRequest" &&
      responseSchema(preview, "200")?.$ref ===
        "#/components/schemas/CustomerCommentPreview" &&
      requestSchema(edit)?.$ref ===
        "#/components/schemas/CustomerPortalCommentEditRequest" &&
      responseSchema(edit, "200")?.$ref ===
        "#/components/schemas/CustomerComment" &&
      responseSchema(history, "200")?.$ref ===
        "#/components/schemas/CustomerCommentRevisionList",
    `${expected.kind} portal schemas drifted`,
  );
  for (const authorityBoundOperation of [
    list,
    create,
    preview,
    edit,
    history,
  ]) {
    const authorization = authorityBoundOperation["x-periapsis-authorization"];
    assert(
      authorization.permission === "portal.comment.public" &&
        authorization.permissionResolution === "same_live_authority_snapshot",
      `${authorityBoundOperation.operationId} must resolve portal comment authority from one live snapshot`,
    );
    exact(
      authorization.requiredPermissions,
      [`portal.${expected.key}.read`],
      `${authorityBoundOperation.operationId} live portal ticket read drifted`,
    );
  }
  const editAuth = edit["x-periapsis-authorization"];
  assert(
    editAuth.authorOnly === "frozen_customer_membership_and_contact" &&
      JSON.stringify(editAuth.editableOrigins) ===
        JSON.stringify(["customer_portal"]) &&
      editAuth.editWindowSeconds === 900 &&
      editAuth.visibility === "public_only_fail_closed" &&
      editAuth.mentions === "forbidden" &&
      editAuth.auditReason === "author_correction" &&
      editAuth.delete === "forbidden" &&
      editAuth.adminOverride === "forbidden",
    `${expected.kind} portal author correction policy drifted`,
  );
  exact(
    parameterRefs(edit),
    [
      "#/components/parameters/CommentIfMatch",
      "#/components/parameters/IdempotencyKey",
    ],
    `${expected.kind} portal edit CAS drifted`,
  );
  assert(
    edit.responses["200"].headers.ETag.$ref ===
      "#/components/headers/CommentStrongETag" &&
      edit.responses["200"].headers["X-Idempotent-Replay"].$ref ===
        "#/components/headers/IdempotentReplay",
    `${expected.kind} portal edit receipt drifted`,
  );
  assertNoStore(preview);
  assertNoStore(list);
  assertNoStore(create);
  assertNoStore(edit);
  assertNoStore(history);
}

function assertNoStore(value) {
  for (const [status, response] of Object.entries(value.responses)) {
    if (Number(status) < 400) {
      assert(
        response.headers?.["Cache-Control"]?.$ref ===
          "#/components/headers/NoStore",
        `${value.operationId} ${status} success must be no-store`,
      );
    } else {
      assert(
        response.$ref?.startsWith("#/components/responses/NoStore") === true,
        `${value.operationId} ${status} must be no-store`,
      );
    }
  }
}

const schemas = document.components.schemas;
assert(
  schemas.CommentMentionCandidateList.properties.items.maxItems === 100 &&
    schemas.CommentMentionCandidateList.properties.items.uniqueItems === true &&
    schemas.CommentMentionCandidateList.properties.items[
      "x-periapsis-unique-by"
    ] === "membershipId" &&
    schemas.CommentMentionCandidateList.description.includes(
      "unique by membershipId",
    ),
  "mention candidates must be bounded and unique by membership identity",
);
exact(
  schemas.CommentOrigin.enum,
  ["api", "customer_portal", "escalation_copy", "system"],
  "comment origin must remain the canonical persistence source vocabulary",
);
assert(
  schemas.CommentOrigin.description.includes(
    "api and system always map to operator",
  ) &&
    schemas.CommentOrigin.description.includes(
      "customer_portal maps to customer",
    ) &&
    schemas.CommentOrigin.description.includes("escalation_copy preserves"),
  "comment origin and frozen author audience mapping must remain explicit",
);
assert(
  schemas.OperatorCommentFrozenAuthor.required.includes("membershipId") &&
    schemas.OperatorCommentFrozenAuthor.description.includes(
      "Every projected origin",
    ) &&
    schemas.OperatorCommentFrozenAuthor.description.includes("system"),
  "every operator comment origin must retain a frozen human membership author",
);
const commentDisplayName = new RegExp(schemas.CommentDisplayName.pattern, "u");
assert(
  schemas.CommentDisplayName.maxLength === 200 &&
    schemas.CommentDisplayName.description.includes("Unicode scalar values") &&
    Array.from("😀".repeat(200)).length === 200,
  "comment display-name length must remain Unicode-scalar bounded",
);
for (const accepted of [
  "Operator One",
  "\uFEFFOperator\uFEFF",
  "A\u2003B",
  "Operator 😀",
]) {
  assert(
    commentDisplayName.test(accepted),
    `comment display name rejected ${JSON.stringify(accepted)}`,
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
  `Operator${String.fromCharCode(0xdc00)}`,
]) {
  assert(
    !commentDisplayName.test(rejected),
    `comment display name accepted ${JSON.stringify(rejected)}`,
  );
}
for (const schemaName of [
  "CommentCreateRequest",
  "CommentEditRequest",
  "CustomerPortalCommentCreate",
  "CustomerPortalCommentPreviewRequest",
  "CustomerPortalCommentEditRequest",
]) {
  const body = schemas[schemaName].properties.bodyMarkdown;
  assert(
    body.maxLength === 20000 &&
      body.description.includes("Unicode scalar values") &&
      body.description.includes("Go strings.TrimSpace"),
    `${schemaName} body length must remain Unicode-scalar bounded`,
  );
  const markdown = new RegExp(body.pattern, "u");
  for (const accepted of [
    "plain text",
    "one\ttwo\nthree",
    "`<script>` evidence",
    "\uFEFF",
    "😀",
  ]) {
    assert(
      markdown.test(accepted),
      `${schemaName} rejected ${JSON.stringify(accepted)}`,
    );
  }
  for (const rejected of [
    " leading",
    "trailing ",
    "\u00a0leading",
    "trailing\u3000",
    "\nleading",
    "trailing\t",
    "one\rtwo",
    "one\u0085two",
    "one\u200etwo",
    "one\u202etwo",
    "one\u2066two",
    String.fromCharCode(0xd800),
  ]) {
    assert(
      !markdown.test(rejected),
      `${schemaName} accepted ${JSON.stringify(rejected)}`,
    );
  }
}
for (const schemaName of [
  "OperatorCommentPreview",
  "CustomerCommentPreview",
  "OperatorComment",
  "CustomerComment",
  "OperatorCommentRevision",
  "CustomerCommentRevision",
]) {
  assert(
    schemas[schemaName].properties.bodyMarkdown.pattern ===
      schemas.CommentCreateRequest.properties.bodyMarkdown.pattern,
    `${schemaName} Markdown projection controls drifted`,
  );
}
const mentionSearch = new RegExp(
  document.components.parameters.CommentMentionSearch.schema.pattern,
  "u",
);
for (const rejected of [
  "Analyst\u200eOne",
  "Analyst\u202eOne",
  "Analyst\u2066One",
  String.fromCharCode(0xd800),
]) {
  assert(
    !mentionSearch.test(rejected),
    `mention search accepted ${JSON.stringify(rejected)}`,
  );
}
const uuidPattern =
  "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])";
assert(
  schemas.CommentRelatedId.pattern === uuidPattern &&
    document.components.parameters.CommentId.schema.pattern === uuidPattern &&
    document.components.parameters.CommentAfterCursor.schema.$ref ===
      "#/components/schemas/CommentRelatedId" &&
    schemas.OperatorCommentList.properties.nextCursor.$ref ===
      "#/components/schemas/CommentRelatedId" &&
    schemas.CustomerCommentList.properties.nextCursor.$ref ===
      "#/components/schemas/CommentRelatedId",
  "comment coordinates must remain canonical UUIDv7",
);
const commentEtagPattern =
  '^"comment-r(?:[1-9][0-9]{0,8}|1[0-9]{9}|20[0-9]{8}|21[0-3][0-9]{7}|214[0-6][0-9]{6}|2147[0-3][0-9]{5}|21474[0-7][0-9]{4}|214748[0-2][0-9]{3}|2147483[0-5][0-9]{2}|21474836[0-3][0-9]|214748364[0-7])"(?![\\s\\S])';
assert(
  schemas.CommentStrongEntityTag.pattern === commentEtagPattern &&
    document.components.parameters.CommentIfMatch.schema.$ref ===
      "#/components/schemas/CommentStrongEntityTag",
  "comment ETag grammar drifted",
);
const etag = new RegExp(commentEtagPattern, "u");
for (const accepted of ['"comment-r1"', '"comment-r2147483647"']) {
  assert(etag.test(accepted), `comment ETag rejected ${accepted}`);
}
for (const rejected of [
  '"comment-r0"',
  '"comment-r01"',
  '"comment-r2147483648"',
  'W/"comment-r1"',
  '"comment-r1"\n',
]) {
  assert(
    !etag.test(rejected),
    `comment ETag accepted ${JSON.stringify(rejected)}`,
  );
}

exact(
  schemas.CommentEditRequest.required,
  ["bodyMarkdown", "reason"],
  "operator edit required fields drifted",
);
assert(
  schemas.CommentEditRequest.additionalProperties === false &&
    schemas.CommentEditRequest.properties.visibility === undefined &&
    schemas.CommentEditRequest.properties.reason.$ref ===
      "#/components/schemas/CommentEditReason" &&
    schemas.CommentEditReason.minLength === 1 &&
    schemas.CommentEditReason.maxLength === 500,
  "operator edit must require a bounded reason and forbid visibility changes",
);
const reason = new RegExp(schemas.CommentEditReason.pattern, "u");
for (const accepted of ["Typo correction", "Clarified timeline"]) {
  assert(reason.test(accepted), `edit reason rejected ${accepted}`);
}
for (const rejected of [
  "",
  "   ",
  "bad\nreason",
  "bad\u200ereason",
  "bad\u202ereason",
  "bad\u2066reason",
  "<unfinished",
  "<script>alert(1)</script>",
  String.fromCharCode(0xd800),
]) {
  assert(
    !reason.test(rejected),
    `edit reason accepted ${JSON.stringify(rejected)}`,
  );
}

for (const name of ["OperatorComment", "CustomerComment"]) {
  const schema = schemas[name];
  assert(
    schema.additionalProperties === false &&
      schema.required.includes("origin") &&
      schema.required.includes("attachments") &&
      schema.required.includes("canEdit") &&
      schema.required.includes("editableUntil"),
    `${name} aggregate metadata drifted`,
  );
  assert(
    schema.properties.author.$ref.endsWith("CommentFrozenAuthor") &&
      schemas[schema.properties.author.$ref.split("/").at(-1)].properties
        .audience !== undefined &&
      schemas[schema.properties.author.$ref.split("/").at(-1)].properties
        .origin === undefined,
    `${name} must separate source origin from frozen author audience`,
  );
  assert(
    schema.properties.canEdit.description.includes(
      "including idempotent replay",
    ) &&
      schema.properties.editableUntil.description.includes(
        "Fixed createdAt plus 15 minutes",
      ),
    `${name} must separate volatile canEdit from immutable editableUntil`,
  );
}
assert(
  schemas.OperatorComment.properties.mentions !== undefined &&
    schemas.CustomerComment.properties.mentions === undefined &&
    schemas.CustomerComment.properties.attachments.items.$ref ===
      "#/components/schemas/CustomerCommentAttachment" &&
    schemas.CustomerCommentAttachment.properties.visibility === undefined,
  "customer comments must structurally omit mentions and private attachment metadata",
);
for (const name of ["OperatorCommentAttachment", "CustomerCommentAttachment"]) {
  const filename = schemas[name].properties.originalFilename;
  assert(
    filename.maxLength === 255 &&
      filename.description.includes("255 UTF-8 bytes"),
    `${name} filename bound drifted`,
  );
  const pattern = new RegExp(filename.pattern, "u");
  for (const accepted of ["evidence.txt", "<harmless>.txt", "résumé.pdf"]) {
    assert(
      pattern.test(accepted),
      `${name} rejected ${JSON.stringify(accepted)}`,
    );
  }
  for (const rejected of [
    ".",
    "..",
    " evidence.txt",
    "evidence.txt\u3000",
    "a/b",
    "a\\b",
    "bad\u0085name",
    "bad\u200ename",
    "bad\u202ename",
    "bad\u2066name",
    String.fromCharCode(0xd800),
  ]) {
    assert(
      !pattern.test(rejected),
      `${name} accepted ${JSON.stringify(rejected)}`,
    );
  }
}
assert(
  schemas.OperatorCommentRevision.required.includes("reason") &&
    schemas.CustomerCommentRevision.properties.reason === undefined &&
    schemas.CustomerCommentRevision.properties.mentions === undefined,
  "revision history reason and mention privacy drifted",
);
for (const name of [
  "CustomerPortalCommentCreate",
  "CustomerPortalCommentPreviewRequest",
  "CustomerPortalCommentEditRequest",
]) {
  assert(
    schemas[name].additionalProperties === false &&
      schemas[name].properties.visibility === undefined &&
      schemas[name].properties.mentionedMembershipIds === undefined &&
      schemas[name].properties.reason === undefined,
    `${name} must remain public-only and mention-free`,
  );
}

const expectedEvents = [
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.watcher_added",
  "case.watcher_removed",
];
for (const event of expectedEvents) {
  assert(
    schemas.NotificationEventType.enum.includes(event),
    `notification event ${event} is missing`,
  );
}

const operationIds = [
  ...operatorKinds.flatMap(({ kind }) => [
    `previewTenant${kind}Comment`,
    `listTenant${kind}CommentMentionCandidates`,
    `editTenant${kind}Comment`,
    `listTenant${kind}CommentRevisions`,
    `previewCustomerPortal${kind}Comment`,
    `editCustomerPortal${kind}Comment`,
    `listCustomerPortal${kind}CommentRevisions`,
  ]),
];
for (const operationId of operationIds) {
  assert(
    generatedSdk.includes(`export const ${operationId} =`),
    `generated TypeScript SDK is missing ${operationId}`,
  );
  const goName = operationId[0].toUpperCase() + operationId.slice(1);
  assert(
    generatedGo.includes(`${goName}(`),
    `generated Go interface is missing ${goName}`,
  );
}
for (const name of [
  "CommentEditRequest",
  "CommentStrongEntityTag",
  "OperatorCommentPreview",
  "CustomerCommentPreview",
  "CommentMentionCandidateList",
  "OperatorCommentRevisionList",
  "CustomerCommentRevisionList",
]) {
  assert(
    generatedTypes.includes(`export type ${name} =`),
    `generated TypeScript type is missing ${name}`,
  );
}

process.stdout.write("Ticket-comment contract invariants verified.\n");
