import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { isIP } from "node:net";
import { sample as sampleOpenAPI } from "openapi-sampler";

export const generatedBy = "openapi-sampler@1.7.4+ajv@8.18.0+ajv-formats@3.0.1";
export const generationStrategy =
  "one-schema-valid-safe-json-request-and-success-response-per-operation-tag";
export const methods = ["get", "post", "put", "patch", "delete"];

const sensitiveKeys = new Set([
  "accesstoken",
  "assertion",
  "bindpassword",
  "challengesecret",
  "challengetoken",
  "clientsecret",
  "credential",
  "credentialvalue",
  "enrollmenttoken",
  "idtoken",
  "password",
  "privatekey",
  "recoverycode",
  "recoverycodes",
  "refreshtoken",
  "secret",
  "token",
  "totpuri",
]);

const forbiddenValues = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bBearer\s+[A-Za-z0-9._~-]+/iu,
  /\bPERIAPSIS_[A-Z0-9_]+/u,
  /\bpostgres(?:ql)?:\/\//iu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u,
];

const normalizedKey = (value) =>
  value.toLowerCase().replaceAll(/[^a-z0-9]/gu, "");

const containsUnreservedEmail = (value) => {
  for (const match of value.matchAll(/[^\s@<>()"',;:]+@([^\s@<>()"',;:]+)/gu)) {
    const domain = match[1].replace(/[.!?]+$/u, "").toLowerCase();
    if (
      domain !== "example.com" &&
      domain !== "example.net" &&
      domain !== "example.org" &&
      domain !== "localhost" &&
      !domain.endsWith(".invalid") &&
      !domain.endsWith(".test")
    ) {
      return true;
    }
  }
  return false;
};

export const containsSensitiveFixture = (value) => {
  if (Array.isArray(value)) return value.some(containsSensitiveFixture);
  if (value !== null && typeof value === "object") {
    return Object.entries(value).some(
      ([key, child]) =>
        sensitiveKeys.has(normalizedKey(key)) ||
        containsSensitiveFixture(child),
    );
  }
  return (
    typeof value === "string" &&
    (containsUnreservedEmail(value) ||
      forbiddenValues.some((pattern) => pattern.test(value)))
  );
};

const decodePointerToken = (value) =>
  decodeURIComponent(value).replaceAll("~1", "/").replaceAll("~0", "~");

export const resolveReference = (document, value) => {
  let current = value;
  const seen = new Set();
  while (current?.$ref !== undefined) {
    const reference = current.$ref;
    if (typeof reference !== "string" || !reference.startsWith("#/")) {
      throw new Error(
        `only local references are supported: ${String(reference)}`,
      );
    }
    if (seen.has(reference)) throw new Error(`reference cycle at ${reference}`);
    seen.add(reference);
    current = reference
      .slice(2)
      .split("/")
      .map(decodePointerToken)
      .reduce((parent, key) => parent?.[key], document);
    if (current === undefined)
      throw new Error(`unresolved reference ${reference}`);
  }
  return current;
};

export const collectOperations = (document) => {
  const operations = [];
  for (const [path, pathItem] of Object.entries(document.paths ?? {})) {
    for (const method of methods) {
      const operation = pathItem[method];
      if (operation !== undefined) operations.push({ method, operation, path });
    }
  }
  return operations;
};

export const jsonRequest = (document, { operation }) =>
  resolveReference(document, operation.requestBody)?.content?.[
    "application/json"
  ];

export const jsonSuccessResponse = (document, { operation }) => {
  for (const status of Object.keys(operation.responses ?? {}).toSorted()) {
    if (!/^2[0-9][0-9]$/u.test(status)) continue;
    const response = resolveReference(document, operation.responses[status]);
    const mediaType = response?.content?.["application/json"];
    if (mediaType !== undefined) return { mediaType, status };
  }
  return undefined;
};

const omitDirectionalProperties = (value, kind) => {
  if (Array.isArray(value)) {
    return value.map((entry) => omitDirectionalProperties(entry, kind));
  }
  if (value === null || typeof value !== "object") return value;

  const clone = Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key,
      omitDirectionalProperties(child, kind),
    ]),
  );
  if (value.properties === undefined) return clone;

  const omitted = new Set(
    Object.entries(value.properties)
      .filter(([, property]) =>
        kind === "request"
          ? property?.readOnly === true
          : property?.writeOnly === true,
      )
      .map(([name]) => name),
  );
  if (omitted.size === 0) return clone;

  clone.properties = Object.fromEntries(
    Object.entries(clone.properties).filter(([name]) => !omitted.has(name)),
  );
  if (Array.isArray(clone.required)) {
    clone.required = clone.required.filter((name) => !omitted.has(name));
  }
  return clone;
};

const createAjv = () => {
  const ajv = new Ajv2020({
    $data: false,
    allErrors: true,
    logger: false,
    strict: false,
  });
  addFormats(ajv);
  ajv.addFormat("ip", {
    type: "string",
    validate: (value) => isIP(value) !== 0,
  });
  ajv.addFormat("cidr", {
    type: "string",
    validate: (value) => {
      const separator = value.lastIndexOf("/");
      if (separator <= 0) return false;
      const version = isIP(value.slice(0, separator));
      const prefix = Number(value.slice(separator + 1));
      return (
        (version === 4 || version === 6) &&
        Number.isInteger(prefix) &&
        prefix >= 0 &&
        prefix <= (version === 4 ? 32 : 128)
      );
    },
  });
  ajv.addFormat("byte", {
    type: "string",
    validate: (value) =>
      value.length % 4 === 0 &&
      /^[A-Za-z0-9+/]*={0,2}$/u.test(value) &&
      Buffer.from(value, "base64").toString("base64") === value,
  });
  for (const format of [
    "binary",
    "double",
    "float",
    "int32",
    "int64",
    "password",
  ]) {
    ajv.addFormat(format, true);
  }
  return ajv;
};

const validatorCache = new WeakMap();

const validatorFor = (document, mediaType, kind) => {
  let documentCache = validatorCache.get(document);
  if (documentCache === undefined) {
    documentCache = new WeakMap();
    validatorCache.set(document, documentCache);
  }
  let mediaCache = documentCache.get(mediaType);
  if (mediaCache === undefined) {
    mediaCache = new Map();
    documentCache.set(mediaType, mediaCache);
  }
  if (mediaCache.has(kind)) return mediaCache.get(kind);

  const schema = omitDirectionalProperties(mediaType.schema, kind);
  const components = omitDirectionalProperties(document.components, kind);
  const validator = createAjv().compile({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    ...schema,
    components,
  });
  mediaCache.set(kind, validator);
  return validator;
};

export const validateMediaTypeExample = (document, mediaType, kind, value) => {
  const validator = validatorFor(document, mediaType, kind);
  const valid = validator(value);
  return {
    errors: valid ? [] : (validator.errors ?? []),
    valid,
  };
};

const schemaLayers = (document, schema, seen = new Set()) => {
  if (schema === null || typeof schema !== "object") return [];
  const layers = [schema];
  if (typeof schema.$ref === "string" && !seen.has(schema.$ref)) {
    const nextSeen = new Set(seen).add(schema.$ref);
    layers.push(
      ...schemaLayers(document, resolveReference(document, schema), nextSeen),
    );
  }
  for (const entry of schema.allOf ?? []) {
    layers.push(...schemaLayers(document, entry, seen));
  }
  return layers;
};

const combinedPropertySchema = (layers, key) => {
  const definitions = layers.flatMap((layer) =>
    layer.properties?.[key] === undefined ? [] : [layer.properties[key]],
  );
  if (definitions.length === 0) return {};
  if (definitions.length === 1) return definitions[0];
  return { allOf: definitions };
};

const matchesSimpleCondition = (condition, value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  if ((condition.required ?? []).some((key) => !(key in value))) return false;
  return Object.entries(condition.properties ?? {}).every(([key, property]) => {
    if (!(key in value)) return true;
    if (property.const !== undefined) return value[key] === property.const;
    if (Array.isArray(property.enum)) return property.enum.includes(value[key]);
    return true;
  });
};

const normalizeSampleValue = (document, schema, value) => {
  const layers = schemaLayers(document, schema);
  const constant = layers.find((layer) => layer.const !== undefined);
  if (constant !== undefined) return structuredClone(constant.const);
  if (Array.isArray(value)) {
    const itemSchema =
      layers.find((layer) => layer.items !== undefined)?.items ?? {};
    const maximum = Math.min(
      ...layers
        .map((layer) => layer.maxItems)
        .filter((limit) => Number.isInteger(limit)),
      Number.POSITIVE_INFINITY,
    );
    const normalized = value
      .map((entry) => normalizeSampleValue(document, itemSchema, entry))
      .slice(0, maximum);
    if (!layers.some((layer) => layer.uniqueItems === true)) return normalized;

    const enumValues = schemaLayers(document, itemSchema).find((layer) =>
      Array.isArray(layer.enum),
    )?.enum;
    const seen = new Set();
    return normalized.flatMap((entry) => {
      const key = JSON.stringify(entry);
      if (!seen.has(key)) {
        seen.add(key);
        return [entry];
      }
      const replacement = enumValues?.find(
        (candidate) => !seen.has(JSON.stringify(candidate)),
      );
      if (replacement === undefined) return [];
      seen.add(JSON.stringify(replacement));
      return [replacement];
    });
  }
  if (typeof value === "string") {
    const pattern = layers.find(
      (layer) => layer.pattern !== undefined,
    )?.pattern;
    const format = layers.find((layer) => layer.format !== undefined)?.format;
    if (pattern === "^[0-9a-f]{64}$") return "0".repeat(64);
    if (pattern === "^[A-Z0-9]{1,4}$") return "P";
    if (pattern === "^[A-Z][A-Z0-9]{0,11}$") return "ALT";
    if (pattern === "^#[0-9a-f]{6}$") return "#2563eb";
    if (pattern === "^(?!und(?:-|$))[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$") {
      return "en";
    }
    if (
      pattern?.startsWith(
        "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
      )
    ) {
      return "018f47b4-86e2-7c4f-8b32-123456789abc";
    }
    if (
      pattern === "^[A-Z][A-Z0-9]{0,11}([-/._])(?:[0-9]{4}\\1)?[0-9]{4,12}$"
    ) {
      return "ALT-2026-000001";
    }
    if (format === "ip" || format === "ipv4") return "192.0.2.1";
    if (format === "ipv6") return "2001:db8::1";
    if (format === "cidr") return "192.0.2.0/24";
    if (format === "byte") return "ZXhhbXBsZQ==";
    if (
      (format === "uri" || format === "uri-reference") &&
      value.startsWith("http://")
    ) {
      return "https://example.invalid/";
    }
    return value;
  }
  if (value === null || typeof value !== "object") return value;

  const required = new Set(layers.flatMap((layer) => layer.required ?? []));
  let normalized = Object.fromEntries(
    Object.entries(value).flatMap(([key, child]) => {
      if (child === null && !required.has(key)) return [];
      return [
        [
          key,
          normalizeSampleValue(
            document,
            combinedPropertySchema(layers, key),
            child,
          ),
        ],
      ];
    }),
  );

  for (const layer of layers.filter((entry) => entry.if !== undefined)) {
    const branch = matchesSimpleCondition(layer.if, normalized)
      ? layer.then
      : layer.else;
    if (branch === undefined) continue;
    normalized = Object.fromEntries(
      Object.entries(normalized).map(([key, child]) => [
        key,
        normalizeSampleValue(
          document,
          {
            allOf: [
              combinedPropertySchema(layers, key),
              branch.properties?.[key] ?? {},
            ],
          },
          child,
        ),
      ]),
    );
  }
  return normalized;
};

export const sampleMediaType = (document, mediaType, kind) => {
  if (mediaType?.schema === undefined) {
    throw new Error(`${kind} media type has no schema`);
  }
  const value = sampleOpenAPI(
    mediaType.schema,
    {
      quiet: true,
      skipNonRequired: true,
      skipReadOnly: kind === "request",
      skipWriteOnly: kind === "response",
    },
    document,
  );
  if (value === undefined)
    throw new Error(`${kind} sampler returned undefined`);
  return normalizeSampleValue(document, mediaType.schema, value);
};

export const formatValidationErrors = (errors) =>
  errors
    .slice(0, 5)
    .map(
      ({ instancePath, keyword, message }) =>
        `${instancePath || "/"} ${keyword} ${message ?? "failed"}`,
    )
    .join("; ");
