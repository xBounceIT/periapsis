import {
  archiveTenantCustomFieldDefinition,
  createTenantCustomFieldDefinition,
  getTenantCustomFieldDefinition,
  getTenantObjectCustomFields,
  listTenantCustomFieldDefinitions,
  replaceTenantCustomFieldDefinition,
  replaceTenantObjectCustomFields,
  type CustomFieldDefinitionSpec,
  type CustomFieldValue,
} from "@periapsis/contracts";
import { z } from "zod";

import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  canEditDefinition,
  customFieldDataTypes,
  type CustomFieldDefinitionView,
  type CustomFieldDrafts,
  type CustomFieldObjectType,
} from "./model";

export interface CustomFieldDefinitionPageView {
  items: CustomFieldDefinitionView[];
  nextCursor?: string;
}

export interface VersionedCustomFieldDefinition {
  etag: string;
  value: CustomFieldDefinitionView;
}

export interface CustomFieldAdministrationApi {
  list(input: {
    after?: string;
    includeArchived?: boolean;
    limit?: number;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldDefinitionPageView>;
  get(input: {
    definitionId: string;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedCustomFieldDefinition>;
  create(input: {
    csrfToken: string;
    definition: CustomFieldDefinitionSpec;
    definitionId: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<VersionedCustomFieldDefinition>;
  replace(input: {
    csrfToken: string;
    definition: CustomFieldDefinitionSpec;
    definitionId: string;
    etag: string;
    expectedVersion: number;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<VersionedCustomFieldDefinition>;
  archive(input: {
    csrfToken: string;
    definitionId: string;
    etag: string;
    expectedVersion: number;
    idempotencyKey: string;
    objectType: CustomFieldObjectType;
    reason: string;
    tenantId: string;
  }): Promise<{ etag: string }>;
}

export interface CustomFieldObjectProjectionView {
  definitions: CustomFieldDefinitionView[];
  drafts: CustomFieldDrafts;
  etag: string;
  objectId: string;
  objectType: CustomFieldObjectType;
  tenantId: string;
  version: number;
}

export interface CustomFieldObjectApi {
  get(input: {
    objectId: string;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldObjectProjectionView>;
  replace(input: {
    csrfToken: string;
    current: CustomFieldObjectProjectionView;
    idempotencyKey: string;
    signal?: AbortSignal;
    tenantId: string;
    values: Readonly<Record<string, CustomFieldValue>>;
  }): Promise<CustomFieldObjectProjectionView>;
}

export class CustomFieldApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "CustomFieldApiError";
    this.status = status;
  }
}

interface GeneratedResult {
  data?: unknown;
  response?: Response;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  cache: "no-store" as const,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const keyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const cursorPattern = /^[A-Za-z0-9_-]{1,256}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const customFieldEtagPattern = /^"cf-[A-Za-z0-9_-]{22}"$/u;
const versionEtagPattern = /^"v[1-9][0-9]*"$/u;
const maximumCustomFieldPageSize = 100;
const maximumCustomFieldCatalogSize = 1_000;

export const customFieldAdministrationApi: CustomFieldAdministrationApi = {
  async list({
    after,
    includeArchived = false,
    limit = 100,
    objectType,
    signal,
    tenantId,
  }) {
    requireUuid(tenantId, "tenant");
    requireObjectType(objectType);
    requirePageSize(limit);
    requireCursor(after);
    const result = await listTenantCustomFieldDefinitions({
      ...sameOrigin,
      path: { tenantId },
      query: {
        objectType,
        includeArchived,
        limit,
        ...(after ? { after } : {}),
      },
      ...(signal ? { signal } : {}),
    });
    requireStatus(result.response, 200);
    const page = definitionPageSchema.parse(result.data);
    if (page.items.length > limit) throw projectionMismatch();
    const items = page.items.map((item) =>
      projectDefinition(item, tenantId, objectType),
    );
    requireUniqueDefinitionIdentities(items);
    return {
      items,
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  },

  async get({ definitionId, objectType, signal, tenantId }) {
    requireCoordinates(tenantId, definitionId, objectType);
    const result = await getTenantCustomFieldDefinition({
      ...sameOrigin,
      path: { tenantId, definitionId },
      query: { objectType },
      ...(signal ? { signal } : {}),
    });
    return projectVersioned(result, tenantId, objectType, definitionId, 200);
  },

  async create({
    csrfToken,
    definition,
    definitionId,
    idempotencyKey,
    tenantId,
  }) {
    requireCoordinates(tenantId, definitionId, definition.objectType);
    requireMutationHeaders(csrfToken, idempotencyKey);
    const result = await createTenantCustomFieldDefinition({
      ...sameOrigin,
      body: { definition, definitionId },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    return projectVersioned(
      result,
      tenantId,
      definition.objectType,
      definitionId,
      201,
    );
  },

  async replace({
    csrfToken,
    definition,
    definitionId,
    etag,
    expectedVersion,
    idempotencyKey,
    tenantId,
  }) {
    requireCoordinates(tenantId, definitionId, definition.objectType);
    requireMutationHeaders(csrfToken, idempotencyKey, etag);
    requireResourceVersion(expectedVersion);
    const result = await replaceTenantCustomFieldDefinition({
      ...sameOrigin,
      body: { definition, expectedVersion },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId, definitionId },
    });
    const projected = projectVersioned(
      result,
      tenantId,
      definition.objectType,
      definitionId,
      200,
    );
    if (projected.value.schemaVersion <= expectedVersion) {
      throw projectionMismatch();
    }
    return projected;
  },

  async archive({
    csrfToken,
    definitionId,
    etag,
    expectedVersion,
    idempotencyKey,
    objectType,
    reason,
    tenantId,
  }) {
    requireCoordinates(tenantId, definitionId, objectType);
    requireMutationHeaders(csrfToken, idempotencyKey, etag);
    requireResourceVersion(expectedVersion);
    if (
      reason.length < 1 ||
      reason.length > 500 ||
      reason.trim() !== reason ||
      containsControlCharacter(reason)
    ) {
      throw new TypeError("A canonical archive reason is required.");
    }
    const result = await archiveTenantCustomFieldDefinition({
      ...sameOrigin,
      body: { expectedVersion, objectType, reason },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId, definitionId },
    });
    requireStatus(result.response, 204);
    return { etag: requireEtag(result.response) };
  },
};

export const customFieldObjectApi: CustomFieldObjectApi = {
  async get({ objectId, objectType, signal, tenantId }) {
    requireObjectCoordinates(tenantId, objectId, objectType);
    const result = await getTenantObjectCustomFields({
      ...sameOrigin,
      path: { tenantId, objectType, objectId },
      query: { surface: "detail" },
      ...(signal ? { signal } : {}),
    });
    return projectObjectProjection(result, tenantId, objectType, objectId);
  },

  async replace({
    csrfToken,
    current,
    idempotencyKey,
    signal,
    tenantId,
    values,
  }) {
    requireObjectCoordinates(tenantId, current.objectId, current.objectType);
    requireReplaceableProjection(current, tenantId, values);
    requireMutationHeaders(csrfToken, idempotencyKey, current.etag);
    requireResourceVersion(current.version);
    requireCustomFieldValues(values);
    const result = await replaceTenantObjectCustomFields({
      ...sameOrigin,
      body: {
        expectedVersion: current.version,
        phase: "update",
        values: { ...values },
      },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": current.etag,
        "X-CSRF-Token": csrfToken,
      },
      path: {
        tenantId,
        objectType: current.objectType,
        objectId: current.objectId,
      },
      ...(signal ? { signal } : {}),
    });
    requireStatus(result.response, 200);
    const response = objectValuesResultSchema.parse(result.data);
    if (response.version <= current.version) throw projectionMismatch();
    return {
      ...current,
      drafts: projectValueDrafts(response.values, current.definitions),
      etag: requireVersionEtag(result.response, response.version),
      version: response.version,
    };
  },
};

export async function listAllCustomFieldDefinitions(
  api: CustomFieldAdministrationApi,
  input: {
    includeArchived?: boolean;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  },
): Promise<CustomFieldDefinitionView[]> {
  const items: CustomFieldDefinitionView[] = [];
  const cursors = new Set<string>();
  const definitionIds = new Set<string>();
  const definitionKeys = new Set<string>();
  let after: string | undefined;
  const maximumPages =
    maximumCustomFieldCatalogSize / maximumCustomFieldPageSize;
  for (let pageIndex = 0; pageIndex < maximumPages; pageIndex += 1) {
    // oxlint-disable-next-line no-await-in-loop -- each opaque cursor is issued by the preceding page.
    const page = await api.list({
      ...input,
      ...(after ? { after } : {}),
      limit: maximumCustomFieldPageSize,
    });
    for (const item of page.items) {
      if (definitionIds.has(item.id) || definitionKeys.has(item.key)) {
        throw projectionMismatch();
      }
      definitionIds.add(item.id);
      definitionKeys.add(item.key);
      items.push(item);
    }
    if (items.length > maximumCustomFieldCatalogSize)
      throw projectionMismatch();
    if (!page.nextCursor) return items;
    if (cursors.has(page.nextCursor)) throw projectionMismatch();
    cursors.add(page.nextCursor);
    after = page.nextCursor;
  }
  throw new CustomFieldApiError(
    "The custom-field catalog exceeds the bounded form projection.",
  );
}

const optionSchema = z
  .object({
    id: z.string().regex(uuidV7Pattern),
    key: z.string().regex(keyPattern),
    label: z.string().min(1).max(256),
    position: z.number().int().min(0).max(65_535),
    archived: z.boolean(),
  })
  .strict();

const constraintsSchema = z
  .object({
    minimumLength: z.number().int().min(0).max(65_536).optional(),
    maximumLength: z.number().int().min(0).max(65_536).optional(),
    minimum: z.string().max(128).optional(),
    maximum: z.string().max(128).optional(),
    pattern: z.string().max(512).optional(),
  })
  .strict();

const definitionSpecSchema = z
  .object({
    objectType: z.enum(["alert", "case"]),
    key: z.string().regex(keyPattern),
    label: z.string().min(1).max(256),
    description: z.string().max(8192),
    dataType: z.enum(customFieldDataTypes),
    required: z.boolean(),
    nullable: z.boolean(),
    defaultValue: z.custom<CustomFieldValue>(isCustomFieldValue).optional(),
    constraints: constraintsSchema.optional(),
    options: z.array(optionSchema).max(512).optional(),
    visibility: z
      .object({ customer: z.boolean(), operator: z.boolean() })
      .strict(),
    editPolicy: z
      .object({
        customerCreate: z.boolean(),
        customerUpdate: z.boolean(),
        operatorCreate: z.boolean(),
        operatorUpdate: z.boolean(),
      })
      .strict(),
    placement: z
      .object({
        showInCreate: z.boolean(),
        showInDetail: z.boolean(),
        showInList: z.boolean(),
        showInExport: z.boolean(),
      })
      .strict(),
    requiredOnTransitions: z.array(z.string().regex(keyPattern)).max(128),
    searchable: z.boolean(),
    filterable: z.boolean(),
    sortable: z.boolean(),
    allowStructuredJson: z.boolean(),
  })
  .strict();

const definitionSchema = z
  .object({
    id: z.string().regex(uuidV7Pattern),
    tenantId: z.string().regex(uuidV7Pattern),
    schemaVersion: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    archived: z.boolean(),
    definition: definitionSpecSchema,
  })
  .strict();

const definitionPageSchema = z
  .object({
    items: z.array(definitionSchema).max(200),
    nextCursor: z.string().regex(cursorPattern).optional(),
  })
  .strict();

const projectedValueSchema = z
  .object({
    key: z.string().regex(keyPattern),
    definitionId: z.string().regex(uuidV7Pattern),
    schemaVersion: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    presence: z.enum(["missing", "null", "present"]),
    value: z.custom<CustomFieldValue>(isCustomFieldValue).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const valid =
      (value.presence === "missing" && value.value === undefined) ||
      (value.presence === "null" && value.value === null) ||
      (value.presence === "present" &&
        value.value !== undefined &&
        value.value !== null);
    if (!valid) {
      context.addIssue({ code: "custom", message: "Presence/value mismatch" });
    }
  });

const objectProjectionSchema = z
  .object({
    objectType: z.enum(["alert", "case"]),
    objectId: z.string().regex(uuidV7Pattern),
    definitions: z.array(definitionSchema).max(100),
    values: z.array(projectedValueSchema).max(100),
    version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

const objectValuesResultSchema = z
  .object({
    values: z.array(projectedValueSchema).max(100),
    version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

function projectVersioned(
  result: GeneratedResult,
  tenantId: string,
  objectType: CustomFieldObjectType,
  definitionId: string,
  status: 200 | 201,
): VersionedCustomFieldDefinition {
  requireStatus(result.response, status);
  const value = projectDefinition(
    definitionSchema.parse(result.data),
    tenantId,
    objectType,
  );
  if (value.id !== definitionId) throw projectionMismatch();
  return { etag: requireEtag(result.response), value };
}

function projectDefinition(
  value: z.infer<typeof definitionSchema>,
  tenantId: string,
  objectType: CustomFieldObjectType,
): CustomFieldDefinitionView {
  if (
    value.tenantId !== tenantId ||
    value.definition.objectType !== objectType ||
    (value.definition.defaultValue !== undefined &&
      !isCustomFieldValue(value.definition.defaultValue))
  ) {
    throw projectionMismatch();
  }
  const definition = value.definition;
  requireCanonicalDefinitionOptions(definition);
  const { constraints, defaultValue, options, ...requiredDefinition } =
    definition;
  return {
    id: value.id,
    tenantId: value.tenantId,
    schemaVersion: value.schemaVersion,
    archived: value.archived,
    ...requiredDefinition,
    ...(constraints ? { constraints } : {}),
    ...(defaultValue !== undefined ? { defaultValue } : {}),
    ...(options ? { options } : {}),
  };
}

function projectObjectProjection(
  result: GeneratedResult,
  tenantId: string,
  objectType: CustomFieldObjectType,
  objectId: string,
): CustomFieldObjectProjectionView {
  requireStatus(result.response, 200);
  const source = objectProjectionSchema.parse(result.data);
  if (source.objectType !== objectType || source.objectId !== objectId) {
    throw projectionMismatch();
  }
  const definitions = source.definitions.map((definition) =>
    projectDefinition(definition, tenantId, objectType),
  );
  requireUniqueDefinitionIdentities(definitions);
  return {
    definitions,
    drafts: projectValueDrafts(source.values, definitions),
    etag: requireVersionEtag(result.response, source.version),
    objectId,
    objectType,
    tenantId,
    version: source.version,
  };
}

function projectValueDrafts(
  values: readonly z.infer<typeof projectedValueSchema>[],
  definitions: readonly CustomFieldDefinitionView[],
): CustomFieldDrafts {
  if (values.length !== definitions.length) throw projectionMismatch();
  const definitionsByKey = new Map(
    definitions.map((definition) => [definition.key, definition]),
  );
  const result: Record<string, CustomFieldDrafts[string]> = {};
  for (const value of values) {
    const definition = definitionsByKey.get(value.key);
    if (
      !definition ||
      Object.hasOwn(result, value.key) ||
      definition.id !== value.definitionId ||
      definition.schemaVersion !== value.schemaVersion
    ) {
      throw projectionMismatch();
    }
    result[value.key] =
      value.presence === "missing"
        ? { presence: "missing" }
        : value.presence === "null"
          ? { presence: "null" }
          : { presence: "present", value: value.value };
  }
  return result;
}

function requireStatus(response: Response | undefined, status: number): void {
  if (response?.status !== status) {
    throw new CustomFieldApiError(
      statusMessage(response?.status),
      response?.status,
    );
  }
  if (response.headers.get("Cache-Control") !== "no-store") {
    throw projectionMismatch();
  }
}

function statusMessage(status: number | undefined): string {
  switch (status) {
    case 401:
      return "Your session is no longer valid.";
    case 403:
      return "Your current access does not include custom fields.";
    case 404:
      return "The custom-field definition is no longer available.";
    case 409:
      return "The definition conflicts with current values or an existing key.";
    case 412:
    case 428:
      return "The definition changed. Reload it before retrying.";
    default:
      return "The custom-field service is temporarily unavailable.";
  }
}

function requireEtag(response: Response | undefined): string {
  const etag = response?.headers.get("ETag") ?? "";
  if (!customFieldEtagPattern.test(etag)) throw projectionMismatch();
  return etag;
}

function requireVersionEtag(
  response: Response | undefined,
  version: number,
): string {
  const etag = response?.headers.get("ETag") ?? "";
  if (etag !== `"v${version}"`) throw projectionMismatch();
  return etag;
}

function requireCoordinates(
  tenantId: string,
  definitionId: string,
  objectType: CustomFieldObjectType,
): void {
  requireUuid(tenantId, "tenant");
  requireUuid(definitionId, "definition");
  requireObjectType(objectType);
}

function requireObjectCoordinates(
  tenantId: string,
  objectId: string,
  objectType: CustomFieldObjectType,
): void {
  requireUuid(tenantId, "tenant");
  requireUuid(objectId, "object");
  requireObjectType(objectType);
}

function requireUuid(value: string, label: string): void {
  if (!uuidV7Pattern.test(value)) {
    throw new TypeError(`A canonical ${label} UUIDv7 is required.`);
  }
}

function requireObjectType(
  value: string,
): asserts value is CustomFieldObjectType {
  if (value !== "alert" && value !== "case") {
    throw new TypeError("A canonical custom-field object type is required.");
  }
}

function requirePageSize(value: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximumCustomFieldPageSize
  ) {
    throw new TypeError(
      `The custom-field page size must be between 1 and ${maximumCustomFieldPageSize}.`,
    );
  }
}

function requireUniqueDefinitionIdentities(
  definitions: readonly CustomFieldDefinitionView[],
): void {
  const ids = new Set<string>();
  const keys = new Set<string>();
  for (const definition of definitions) {
    if (ids.has(definition.id) || keys.has(definition.key)) {
      throw projectionMismatch();
    }
    ids.add(definition.id);
    keys.add(definition.key);
  }
}

function requireCanonicalDefinitionOptions(
  definition: z.infer<typeof definitionSpecSchema>,
): void {
  const options = definition.options ?? [];
  const selectType =
    definition.dataType === "single_select" ||
    definition.dataType === "multi_select";
  if (selectType !== options.length > 0) throw projectionMismatch();
  if (selectType && !options.some((option) => !option.archived)) {
    throw projectionMismatch();
  }
  const ids = new Set<string>();
  const keys = new Set<string>();
  const positions = new Set<number>();
  for (const option of options) {
    if (
      ids.has(option.id) ||
      keys.has(option.key) ||
      positions.has(option.position)
    ) {
      throw projectionMismatch();
    }
    ids.add(option.id);
    keys.add(option.key);
    positions.add(option.position);
  }
}

function requireCursor(value: string | undefined): void {
  if (value !== undefined && !cursorPattern.test(value)) {
    throw new TypeError("The custom-field cursor is not canonical.");
  }
}

function requireMutationHeaders(
  csrfToken: string,
  idempotencyKey: string,
  etag?: string,
): void {
  if (!csrfToken || containsControlCharacter(csrfToken)) {
    throw new TypeError("A CSRF token is required.");
  }
  if (!idempotencyKeyPattern.test(idempotencyKey)) {
    throw new TypeError("A canonical idempotency key is required.");
  }
  if (
    etag !== undefined &&
    !customFieldEtagPattern.test(etag) &&
    !versionEtagPattern.test(etag)
  ) {
    throw new TypeError("A strong custom-field ETag is required.");
  }
}

function requireResourceVersion(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError("A positive resource version is required.");
  }
}

function requireCustomFieldValues(
  values: Readonly<Record<string, CustomFieldValue>>,
): void {
  const entries = Object.entries(values);
  if (
    entries.length > 100 ||
    entries.some(
      ([key, value]) => !keyPattern.test(key) || !isCustomFieldValue(value),
    )
  ) {
    throw new TypeError("Canonical bounded custom-field values are required.");
  }
}

function requireReplaceableProjection(
  current: CustomFieldObjectProjectionView,
  tenantId: string,
  values: Readonly<Record<string, CustomFieldValue>>,
): void {
  if (current.tenantId !== tenantId) throw projectionMismatch();
  requireUniqueDefinitionIdentities(current.definitions);
  const definitions = new Map(
    current.definitions.map((definition) => [definition.key, definition]),
  );
  for (const definition of current.definitions) {
    if (
      definition.tenantId !== tenantId ||
      definition.objectType !== current.objectType ||
      !definition.placement.showInDetail
    ) {
      throw projectionMismatch();
    }
  }
  for (const key of Object.keys(values)) {
    const definition = definitions.get(key);
    if (!definition || !canEditDefinition(definition, "operator", "update")) {
      throw new TypeError(
        "Custom-field updates must stay inside the editable detail projection.",
      );
    }
  }
}

function isCustomFieldValue(
  value: unknown,
  depth = 0,
): value is CustomFieldValue {
  if (depth > 32 || value === undefined) return false;
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return typeof value !== "string" || value.length <= 10_000;
  }
  if (Array.isArray(value)) {
    return (
      value.length <= 100 &&
      value.every(
        (item) =>
          typeof item === "boolean" ||
          (typeof item === "number" && Number.isFinite(item)) ||
          (typeof item === "string" && item.length <= 1_000),
      )
    );
  }
  if (typeof value !== "object") return false;
  try {
    if (new TextEncoder().encode(JSON.stringify(value)).length > 65_536) {
      return false;
    }
  } catch {
    return false;
  }
  const entries = Object.entries(value);
  const budget = { remaining: 4_096 };
  return (
    entries.length <= 100 &&
    entries.every(
      ([key, item]) =>
        key.length <= 1_000 &&
        !containsControlCharacter(key) &&
        isStructuredJsonValue(item, depth + 1, budget),
    )
  );
}

function isStructuredJsonValue(
  value: unknown,
  depth: number,
  budget: { remaining: number },
): boolean {
  budget.remaining -= 1;
  if (depth > 32 || budget.remaining < 0) return false;
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return true;
  }
  if (Array.isArray(value)) {
    return (
      value.length <= 4_096 &&
      value.every((item) => isStructuredJsonValue(item, depth + 1, budget))
    );
  }
  if (typeof value !== "object") return false;
  const entries = Object.entries(value);
  return (
    entries.length <= 4_096 &&
    entries.every(
      ([key, item]) =>
        key.length <= 1_000 &&
        !containsControlCharacter(key) &&
        isStructuredJsonValue(item, depth + 1, budget),
    )
  );
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f ||
        (codePoint >= 0x7f && codePoint <= 0x9f) ||
        (codePoint >= 0x202a && codePoint <= 0x202e) ||
        (codePoint >= 0x2066 && codePoint <= 0x2069))
    ) {
      return true;
    }
  }
  return false;
}

function projectionMismatch(): CustomFieldApiError {
  return new CustomFieldApiError(
    "The custom-field response was not canonical.",
  );
}
