import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  collectOperations,
  jsonRequest,
  resolveReference,
  validateMediaTypeExample,
} from "./api-example-support.mjs";

const document = JSON.parse(
  readFileSync(
    new URL(
      "../../../services/api/internal/contract/openapi.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const schemas = document.components.schemas;
const requestSchemaNames = [
  "DfirSharedResourceLinkRequest",
  "DfirSharedResourceUnlinkRequest",
  "DfirIndicatorReplaceRequest",
  "DfirAssetReplaceRequest",
  "DfirTaskTransitionRequest",
  "DfirTaskDetailsRequest",
  "DfirTaskAssignmentRequest",
  "DfirTaskDueDateRequest",
  "DfirTaskChecklistRequest",
  "DfirTaskCommentsRequest",
  "DfirRelationshipRetractRequest",
  "DfirAlertTaskTransitionRequest",
  "DfirAlertTaskAssignmentRequest",
  "DfirAlertTaskDueDateRequest",
  "DfirAlertTaskChecklistRequest",
  "DfirAlertRelationshipRetractRequest",
];
const expectedRef = "#/components/schemas/DfirExpectedResourceVersion";

for (const name of requestSchemaNames) {
  test(`${name} accepts only incrementable exact DFIR revisions`, () => {
    const schema = schemas[name];
    assert.ok(schema.required.includes("expectedVersion"));
    assert.equal(schema.properties.expectedVersion.$ref, expectedRef);
    const mediaType = { schema: schema.properties.expectedVersion };
    for (const value of [1, 2_147_483_648, Number.MAX_SAFE_INTEGER - 1]) {
      assert.equal(
        validateMediaTypeExample(document, mediaType, "request", value).valid,
        true,
      );
    }
    for (const value of [
      0,
      -1,
      1.5,
      "1",
      null,
      Number.MAX_SAFE_INTEGER,
      Number.MAX_SAFE_INTEGER + 1,
    ]) {
      assert.equal(
        validateMediaTypeExample(document, mediaType, "request", value).valid,
        false,
      );
    }
  });
}

test("every incrementable DFIR request is bound to an actual Case or Alert operation", () => {
  const bound = new Set();
  const roots = new Set();
  for (const entry of collectOperations(document)) {
    if (!entry.path.includes("/dfir/")) continue;
    const mediaType = jsonRequest(document, entry);
    if (mediaType === undefined) continue;
    const schema = resolveReference(document, mediaType.schema);
    const versionRef = schema.properties?.expectedVersion?.$ref;
    assert.notEqual(
      versionRef,
      "#/components/schemas/DfirResourceVersion",
      entry.operation.operationId,
    );
    if (versionRef !== expectedRef) continue;
    bound.add(mediaType.schema.$ref.replace("#/components/schemas/", ""));
    roots.add(entry.path.includes("/cases/") ? "case" : "alert");
  }
  assert.deepEqual([...bound].sort(), [...requestSchemaNames].sort());
  assert.deepEqual([...roots].sort(), ["alert", "case"]);
});

test("DFIR snapshots preserve the terminal revision returned by the last increment", () => {
  for (const name of [
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
    const mediaType = { schema: schemas[name].properties.version };
    assert.equal(
      mediaType.schema.$ref,
      "#/components/schemas/DfirResourceVersion",
    );
    assert.equal(
      validateMediaTypeExample(
        document,
        mediaType,
        "response",
        Number.MAX_SAFE_INTEGER,
      ).valid,
      true,
      name,
    );
    assert.equal(
      validateMediaTypeExample(
        document,
        mediaType,
        "response",
        Number.MAX_SAFE_INTEGER + 1,
      ).valid,
      false,
      name,
    );
  }
});

test("custody and legacy ticket revisions keep their separate existing ceilings", () => {
  assert.equal(schemas.ExpectedResourceVersion.maximum, 2_147_483_647);
  assert.equal(schemas.DfirCustodyExpectedVersion.maximum, 999);
  assert.equal(schemas.DfirCustodySequence.maximum, 1000);
  for (const name of [
    "DfirCustodyAppendRequest",
    "DfirAlertCustodyAppendRequest",
  ]) {
    assert.equal(
      schemas[name].properties.expectedVersion.$ref,
      "#/components/schemas/DfirCustodyExpectedVersion",
    );
  }
});
