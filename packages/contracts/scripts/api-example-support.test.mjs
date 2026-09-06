import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

import {
  containsSensitiveFixture,
  generatedBy,
  sampleMediaType,
  validateMediaTypeExample,
} from "./api-example-support.mjs";

test("generator provenance matches the installed example toolchain", () => {
  const require = createRequire(import.meta.url);
  const versions = ["openapi-sampler", "ajv", "ajv-formats"].map(
    (name) => `${name}@${require(`${name}/package.json`).version}`,
  );
  assert.equal(generatedBy, versions.join("+"));
});

test("example validation rejects data-supplied patterns but permits static patterns", () => {
  const exampleDocument = { components: {} };
  const mediaType = {
    schema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        value: { type: "string", pattern: { $data: "1/pattern" } },
      },
    },
  };
  assert.throws(
    () =>
      validateMediaTypeExample(exampleDocument, mediaType, "request", {
        pattern: "^example$",
        value: "example",
      }),
    /schema is invalid.*pattern/u,
  );
  const staticMediaType = { schema: { type: "string", pattern: "^example$" } };
  assert.equal(
    validateMediaTypeExample(
      exampleDocument,
      staticMediaType,
      "request",
      "example",
    ).valid,
    true,
  );
  assert.equal(
    validateMediaTypeExample(
      exampleDocument,
      staticMediaType,
      "request",
      "different",
    ).valid,
    false,
  );
});

const document = {
  components: {
    schemas: {
      DirectionalPayload: {
        additionalProperties: false,
        properties: {
          createdAt: { format: "date-time", readOnly: true, type: "string" },
          name: { minLength: 1, type: "string" },
          writeProof: { type: "string", writeOnly: true },
        },
        required: ["name", "createdAt", "writeProof"],
        type: "object",
      },
      EffectPlan: {
        items: { enum: ["activity", "audit", "notification"], type: "string" },
        minItems: 2,
        uniqueItems: true,
        type: "array",
      },
      SafeIdentifiers: {
        additionalProperties: false,
        properties: {
          blob: { format: "byte", type: "string" },
          endpoint: { format: "uri", type: "string" },
          digest: { pattern: "^[0-9a-f]{64}$", type: "string" },
          id: {
            format: "uuid",
            pattern:
              "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            type: "string",
          },
          network: { format: "cidr", type: "string" },
          sourceAddress: { format: "ip", type: "string" },
        },
        required: [
          "id",
          "digest",
          "sourceAddress",
          "network",
          "blob",
          "endpoint",
        ],
        type: "object",
      },
    },
  },
};

test("normalizes deterministic schema-valid UUIDv7, digest, and unique samples", () => {
  for (const schemaName of ["SafeIdentifiers", "EffectPlan"]) {
    const mediaType = {
      schema: { $ref: `#/components/schemas/${schemaName}` },
    };
    const sample = sampleMediaType(document, mediaType, "response");
    assert.equal(
      validateMediaTypeExample(document, mediaType, "response", sample).valid,
      true,
    );
    assert.deepEqual(sample, sampleMediaType(document, mediaType, "response"));
    if (schemaName === "SafeIdentifiers") {
      assert.equal(sample.endpoint, "https://example.invalid/");
      assert.equal(sample.sourceAddress, "192.0.2.1");
      assert.equal(sample.network, "192.0.2.0/24");
    }
  }
});

test("validates request and response examples with OpenAPI directional fields", () => {
  const mediaType = {
    schema: { $ref: "#/components/schemas/DirectionalPayload" },
  };
  const request = sampleMediaType(document, mediaType, "request");
  const response = sampleMediaType(document, mediaType, "response");

  assert.equal(Object.hasOwn(request, "createdAt"), false);
  assert.equal(Object.hasOwn(response, "writeProof"), false);
  assert.equal(
    validateMediaTypeExample(document, mediaType, "request", request).valid,
    true,
  );
  assert.equal(
    validateMediaTypeExample(document, mediaType, "response", response).valid,
    true,
  );
  assert.equal(
    validateMediaTypeExample(document, mediaType, "response", {
      name: "missing",
    }).valid,
    false,
  );
});

test("rejects credential-shaped example fixtures", () => {
  assert.equal(
    containsSensitiveFixture({
      displayName: "Example analyst",
      email: "analyst@example.com",
    }),
    false,
  );
  assert.equal(containsSensitiveFixture({ password: "example" }), true);
  assert.equal(
    containsSensitiveFixture({ note: "Contact person@company.example today." }),
    true,
  );
  assert.equal(
    containsSensitiveFixture({ endpoint: "postgresql://example.invalid/db" }),
    true,
  );
});

test("rejects invalid custom-format examples", () => {
  const mediaType = {
    schema: { $ref: "#/components/schemas/SafeIdentifiers" },
  };
  const sample = sampleMediaType(document, mediaType, "response");
  assert.equal(
    validateMediaTypeExample(document, mediaType, "response", {
      ...sample,
      network: "192.0.2.0/99",
    }).valid,
    false,
  );
  assert.equal(
    validateMediaTypeExample(document, mediaType, "response", {
      ...sample,
      blob: "not base64",
    }).valid,
    false,
  );
});
