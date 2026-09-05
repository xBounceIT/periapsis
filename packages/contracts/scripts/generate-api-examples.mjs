import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  collectOperations,
  containsSensitiveFixture,
  formatValidationErrors,
  generatedBy,
  generationStrategy,
  jsonRequest,
  jsonSuccessResponse,
  sampleMediaType,
  validateMediaTypeExample,
} from "./api-example-support.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const contractPath = resolve(
  repositoryRoot,
  "services/api/internal/contract/openapi.json",
);
const document = JSON.parse(readFileSync(contractPath, "utf8"));
const operations = collectOperations(document);

const assert = (condition, message) => {
  if (!condition) throw new Error(`API example generation failed: ${message}`);
};

const operationTags = new Set(
  operations.flatMap(({ operation }) => operation.tags ?? []),
);
assert(operationTags.size > 0, "the contract has no tagged operations");

const methodRank = new Map([
  ["get", 0],
  ["post", 1],
  ["put", 2],
  ["patch", 3],
  ["delete", 4],
]);
const compareText = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const pathDepth = (path) => path.split("/").filter(Boolean).length;
const candidateOrder = (left, right) =>
  pathDepth(left.path) - pathDepth(right.path) ||
  (methodRank.get(left.method) ?? 99) - (methodRank.get(right.method) ?? 99) ||
  compareText(left.path, right.path) ||
  compareText(
    String(left.operation.operationId),
    String(right.operation.operationId),
  );

const candidatesFor = (tag, kind) => {
  const failures = [];
  const candidates = operations
    .filter(({ operation }) => operation.tags?.includes(tag))
    .toSorted(candidateOrder);
  for (const entry of candidates) {
    const target =
      kind === "request"
        ? jsonRequest(document, entry)
        : jsonSuccessResponse(document, entry);
    if (target === undefined) continue;
    const mediaType = kind === "request" ? target : target.mediaType;
    try {
      const value = sampleMediaType(document, mediaType, kind);
      if (containsSensitiveFixture(value)) {
        failures.push(`${entry.operation.operationId}: sensitive fixture`);
        continue;
      }
      const validation = validateMediaTypeExample(
        document,
        mediaType,
        kind,
        value,
      );
      if (!validation.valid) {
        failures.push(
          `${entry.operation.operationId}: ${formatValidationErrors(validation.errors)}`,
        );
        continue;
      }
      return {
        candidate: {
          ...entry,
          mediaType,
          status: kind === "response" ? target.status : undefined,
          value,
        },
        failures,
      };
    } catch (error) {
      failures.push(`${entry.operation.operationId}: ${error.message}`);
    }
  }
  return { candidate: undefined, failures };
};

const exampleKey = (tag, kind) =>
  `generated${tag
    .replaceAll(/[^A-Za-z0-9]+/gu, " ")
    .split(" ")
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join("")}${kind === "request" ? "Request" : "Response"}`;

const matchingMediaTypes = (tag, kind, schema) => [
  ...new Set(
    operations
      .filter(({ operation }) => operation.tags?.includes(tag))
      .flatMap((entry) => {
        const target =
          kind === "request"
            ? jsonRequest(document, entry)
            : jsonSuccessResponse(document, entry)?.mediaType;
        return target !== undefined &&
          JSON.stringify(target.schema) === JSON.stringify(schema)
          ? [target]
          : [];
      }),
  ),
];

const coverage = {};
const exampleKeyOwners = new Map();
for (const tag of [...operationTags].toSorted()) {
  coverage[tag] = {};
  const taggedOperations = operations.filter(({ operation }) =>
    operation.tags?.includes(tag),
  );
  const hasJSONRequest = taggedOperations.some(
    (entry) => jsonRequest(document, entry) !== undefined,
  );

  for (const kind of ["request", "response"]) {
    if (kind === "request" && !hasJSONRequest) continue;
    const { candidate, failures } = candidatesFor(tag, kind);
    assert(
      candidate !== undefined,
      `${tag} has no valid safe JSON ${kind} candidate (${failures.join(" | ")})`,
    );
    assert(
      candidate.mediaType.example === undefined,
      `${candidate.operation.operationId} already uses singular media-type example`,
    );
    const key = exampleKey(tag, kind);
    const owner = `${tag}:${kind}`;
    assert(
      !exampleKeyOwners.has(key) || exampleKeyOwners.get(key) === owner,
      `${owner} collides with ${exampleKeyOwners.get(key)} at ${key}`,
    );
    exampleKeyOwners.set(key, owner);
    const example = {
      summary: `Generated ${kind} example for ${tag}`,
      value: candidate.value,
    };
    for (const mediaType of matchingMediaTypes(
      tag,
      kind,
      candidate.mediaType.schema,
    )) {
      assert(
        mediaType.example === undefined,
        `${candidate.operation.operationId} equivalent media type uses singular example`,
      );
      assert(
        mediaType.examples?.[key] === undefined,
        `${candidate.operation.operationId} equivalent media type already uses ${key}`,
      );
      mediaType.examples ??= {};
      mediaType.examples[key] = example;
    }
    coverage[tag][kind] = {
      exampleKey: key,
      method: candidate.method,
      operationId: candidate.operation.operationId,
      path: candidate.path,
      ...(candidate.status === undefined ? {} : { status: candidate.status }),
    };
  }
}

document["x-periapsis-generated-examples"] = {
  coverage,
  generatedBy,
  strategy: generationStrategy,
};

writeFileSync(contractPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
