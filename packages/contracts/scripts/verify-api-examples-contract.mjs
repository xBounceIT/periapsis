import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  collectOperations,
  containsSensitiveFixture,
  formatValidationErrors,
  generatedBy,
  generationStrategy,
  jsonRequest,
  resolveReference,
  sampleMediaType,
  validateMediaTypeExample,
} from "./api-example-support.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);

const fail = (message) => {
  throw new Error(`API example contract invariant failed: ${message}`);
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

const operationEntries = collectOperations(document);
const mediaTypeOwners = new WeakMap();
const recordMediaTypeOwners = (mediaType, kind, tags) => {
  if (mediaType === undefined) return;
  const owners = mediaTypeOwners.get(mediaType) ?? new Set();
  for (const tag of tags) owners.add(`${tag}:${kind}`);
  mediaTypeOwners.set(mediaType, owners);
};
for (const { operation } of operationEntries) {
  const tags = operation.tags ?? [];
  recordMediaTypeOwners(
    resolveReference(document, operation.requestBody)?.content?.[
      "application/json"
    ],
    "request",
    tags,
  );
  for (const response of Object.values(operation.responses ?? {})) {
    recordMediaTypeOwners(
      resolveReference(document, response)?.content?.["application/json"],
      "response",
      tags,
    );
  }
}
const operationTags = [
  ...new Set(operationEntries.flatMap(({ operation }) => operation.tags ?? [])),
].toSorted();
const declaredTags = [
  ...new Set((document.tags ?? []).map(({ name }) => name)),
].toSorted();
exact(
  declaredTags,
  operationTags,
  "declared and operation tag catalogs drifted",
);

const metadata = document["x-periapsis-generated-examples"];
assert(
  metadata?.generatedBy === generatedBy,
  "generator pin is missing or stale",
);
assert(
  metadata?.strategy === generationStrategy,
  "generation strategy is missing or stale",
);
exact(
  Object.keys(metadata.coverage ?? {}).toSorted(),
  operationTags,
  "tag coverage drifted",
);
const expectedGeneratedExamples = new Map();
for (const [tag, entries] of Object.entries(metadata.coverage)) {
  for (const [kind, entry] of Object.entries(entries)) {
    const owner = { kind, tag };
    const ownerLabel = `${tag}:${kind}`;
    assert(
      !expectedGeneratedExamples.has(entry.exampleKey),
      `${ownerLabel} collides with ${JSON.stringify(expectedGeneratedExamples.get(entry.exampleKey))} at ${entry.exampleKey}`,
    );
    expectedGeneratedExamples.set(entry.exampleKey, owner);
  }
}

const locateOperation = ({ method, operationId, path }) => {
  const operation = document.paths?.[path]?.[method];
  assert(operation !== undefined, `${method.toUpperCase()} ${path} is missing`);
  assert(operation.operationId === operationId, `${path} operationId drifted`);
  return operation;
};

const resolveCoverageMediaType = (kind, entry, operation) => {
  if (kind === "request") {
    return resolveReference(document, operation.requestBody)?.content?.[
      "application/json"
    ];
  }
  const response = resolveReference(
    document,
    operation.responses?.[entry.status],
  );
  return response?.content?.["application/json"];
};

const verifyExample = (mediaType, kind, example, coordinate, reproducible) => {
  assert(example?.value !== undefined, `${coordinate} example is missing`);
  assert(
    !containsSensitiveFixture(example.value),
    `${coordinate} example contains credential-like data`,
  );
  const validation = validateMediaTypeExample(
    document,
    mediaType,
    kind,
    example.value,
  );
  assert(
    validation.valid,
    `${coordinate} example violates its schema: ${formatValidationErrors(validation.errors)}`,
  );
  if (reproducible) {
    exact(
      example.value,
      sampleMediaType(document, mediaType, kind),
      `${coordinate} example is not reproducible`,
    );
  }
};

for (const tag of operationTags) {
  const taggedOperations = operationEntries.filter(({ operation }) =>
    operation.tags?.includes(tag),
  );
  const requestExpected = taggedOperations.some(
    (entry) => jsonRequest(document, entry) !== undefined,
  );
  const kinds = requestExpected ? ["request", "response"] : ["response"];
  exact(
    Object.keys(metadata.coverage[tag]).toSorted(),
    kinds.toSorted(),
    `${tag} kinds drifted`,
  );

  for (const kind of kinds) {
    const entry = metadata.coverage[tag][kind];
    const operation = locateOperation(entry);
    assert(
      operation.tags?.includes(tag),
      `${entry.operationId} no longer has tag ${tag}`,
    );
    const mediaType = resolveCoverageMediaType(kind, entry, operation);
    assert(
      mediaType?.schema !== undefined,
      `${tag} ${kind} JSON schema is missing`,
    );
    const example = mediaType.examples?.[entry.exampleKey];
    verifyExample(mediaType, kind, example, `${tag} ${kind}`, true);
  }
}

const observedGeneratedExamples = new Set();
const verifyMediaType = (mediaType, kind, coordinate) => {
  if (mediaType?.schema === undefined) return;
  if (mediaType.example !== undefined) {
    verifyExample(
      mediaType,
      kind,
      { value: mediaType.example },
      `${coordinate} singular`,
      false,
    );
  }
  for (const [key, example] of Object.entries(mediaType.examples ?? {})) {
    const generated = key.startsWith("generated");
    if (generated) {
      const owner = expectedGeneratedExamples.get(key);
      assert(
        owner !== undefined,
        `${coordinate} contains orphan generated example ${key}`,
      );
      assert(
        owner.kind === kind &&
          mediaTypeOwners.get(mediaType)?.has(`${owner.tag}:${owner.kind}`),
        `${coordinate} contains ${key} owned by ${owner.tag}:${owner.kind}`,
      );
      observedGeneratedExamples.add(key);
    }
    verifyExample(mediaType, kind, example, `${coordinate} ${key}`, generated);
  }
};

for (const { method, operation, path } of operationEntries) {
  verifyMediaType(
    resolveReference(document, operation.requestBody)?.content?.[
      "application/json"
    ],
    "request",
    `${method.toUpperCase()} ${path} request`,
  );
  for (const [status, response] of Object.entries(operation.responses ?? {})) {
    verifyMediaType(
      resolveReference(document, response)?.content?.["application/json"],
      "response",
      `${method.toUpperCase()} ${path} response ${status}`,
    );
  }
}
exact(
  [...observedGeneratedExamples].toSorted(),
  [...expectedGeneratedExamples.keys()].toSorted(),
  "generated example inventory drifted",
);
