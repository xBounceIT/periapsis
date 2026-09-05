import {
  listPlatformAuditEvents,
  listTenantAuditEvents,
  verifyPlatformAuditChain,
  verifyTenantAuditChain,
  type AuditActorType,
  type AuditChainVerification,
  type AuditEvent,
  type AuditJsonDocument,
  type AuditOutcome,
} from "@periapsis/contracts";

import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  isAuditTenantId,
  normalizeAuditFilters,
  type AuditFilterDraft,
  type AuditQuery,
} from "./model";

export interface AuditPage {
  items: AuditEvent[];
  nextSequence?: number;
}

export interface AuditListInput {
  afterSequence?: number;
  filters: AuditQuery;
  signal?: AbortSignal;
}

export interface AuditReaderApi {
  listTenant(input: AuditListInput & { tenantId: string }): Promise<AuditPage>;
  listPlatform(input: AuditListInput): Promise<AuditPage>;
  verifyTenant(input: {
    csrfToken: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<AuditChainVerification>;
  verifyPlatform(input: {
    csrfToken: string;
    signal?: AbortSignal;
  }): Promise<AuditChainVerification>;
}

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

const eventKeys = new Set([
  "id",
  "tenantId",
  "sequence",
  "occurredAt",
  "actorType",
  "actorUserId",
  "actorServiceAccountId",
  "impersonatedByUserId",
  "action",
  "resourceType",
  "resourceId",
  "requestId",
  "correlationId",
  "ipAddress",
  "userAgent",
  "authenticationMethod",
  "outcome",
  "reason",
  "before",
  "after",
  "metadata",
  "previousHash",
  "eventHash",
]);
const pageKeys = new Set(["items", "nextSequence"]);
const verificationKeys = new Set([
  "eventCount",
  "lastSequence",
  "retainedThroughSequence",
  "firstInvalidSequence",
  "headValid",
  "valid",
  "verifiedAt",
]);
const stableKeyPattern = /^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*$/u;
const authenticationMethodPattern = /^[a-z][a-z0-9_.:+-]{0,63}$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const hashPattern = /^[0-9a-f]{64}$/u;
const zeroHash = "0".repeat(64);
const maximumSequence = Number.MAX_SAFE_INTEGER;
const maximumDocumentBytes = 64 * 1024;
const maximumMetadataBytes = 16 * 1024;
const maximumJsonDepth = 32;
const maximumJsonNodes = 8_192;

const prohibitedKeys = new Set([
  "accesstoken",
  "accesstokendigest",
  "apikey",
  "apikeydigest",
  "assertion",
  "authorization",
  "bindpassword",
  "clientassertion",
  "clientsecret",
  "cookie",
  "credential",
  "credentials",
  "csrfsecret",
  "csrfsecretdigest",
  "csrftoken",
  "encryptionkey",
  "idtoken",
  "idtokendigest",
  "keymaterial",
  "passphrase",
  "password",
  "passwordphc",
  "privatekey",
  "privatekeyciphertext",
  "recoverycode",
  "recoverycodes",
  "refreshtoken",
  "refreshtokendigest",
  "samlassertion",
  "secret",
  "secretciphertext",
  "sessiontoken",
  "token",
  "tokendigest",
  "totpsecret",
]);
const sensitiveKeyFragments = [
  "accesstoken",
  "apikey",
  "assertion",
  "bindpassword",
  "clientassertion",
  "clientsecret",
  "cookie",
  "credential",
  "csrfsecret",
  "csrftoken",
  "encryptionkey",
  "idtoken",
  "keymaterial",
  "passphrase",
  "password",
  "privatekey",
  "recoverycode",
  "refreshtoken",
  "samlassertion",
  "secret",
  "sessiontoken",
  "token",
  "totpsecret",
];
const safeSensitiveBooleanKeys = new Set([
  "authorizationinitialized",
  "bindsecretconfigured",
  "passwordconfigured",
  "privatekeyconfigured",
  "secretmaterialarchived",
  "secretmaterialincluded",
]);
const safeSensitiveIdentifierKeys = new Set([
  "apikeyid",
  "bindsecretid",
  "credentialid",
  "fencetoken",
  "predecessorcredentialid",
  "replacementcredentialid",
  "secretid",
]);
const safeSensitiveIntegerKeys = new Set([
  "authorizationrevision",
  "bindsecretkeyversion",
  "bindsecretversion",
  "credentialkeyversion",
  "credentialversion",
  "secretversion",
]);
const safeSensitiveKindKeys = new Set([
  "bindsecretalgorithm",
  "credentialkind",
  "secretkind",
  "tokenkind",
]);

export const auditReaderApi: AuditReaderApi = {
  async listTenant({ afterSequence, filters, signal, tenantId }) {
    requireTenant(tenantId);
    const query = normalizeQuery(filters, "tenant");
    const result = await listTenantAuditEvents({
      ...requestDefaults(),
      path: { tenantId },
      query: {
        ...query,
        ...(afterSequence === undefined ? {} : { afterSequence }),
      },
      ...(signal ? { signal } : {}),
    });
    return projectPage(
      unwrap(result),
      result.response,
      { kind: "tenant", tenantId },
      query,
      afterSequence ?? 0,
    );
  },

  async listPlatform({ afterSequence, filters, signal }) {
    const query = normalizeQuery(filters, "platform");
    const result = await listPlatformAuditEvents({
      ...requestDefaults(),
      query: {
        ...query,
        ...(afterSequence === undefined ? {} : { afterSequence }),
      },
      ...(signal ? { signal } : {}),
    });
    return projectPage(
      unwrap(result),
      result.response,
      { kind: "platform" },
      query,
      afterSequence ?? 0,
    );
  },

  async verifyTenant({ csrfToken, signal, tenantId }) {
    requireTenant(tenantId);
    requireCsrf(csrfToken);
    const result = await verifyTenantAuditChain({
      ...requestDefaults(),
      headers: { "X-CSRF-Token": csrfToken },
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    return projectVerification(unwrap(result), result.response);
  },

  async verifyPlatform({ csrfToken, signal }) {
    requireCsrf(csrfToken);
    const result = await verifyPlatformAuditChain({
      ...requestDefaults(),
      headers: { "X-CSRF-Token": csrfToken },
      ...(signal ? { signal } : {}),
    });
    return projectVerification(unwrap(result), result.response);
  },
};

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    cache: "no-store" as const,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function normalizeQuery(filters: AuditQuery, surface: "tenant" | "platform") {
  const draft: AuditFilterDraft = {
    ...filters,
    actionPrefix: filters.actionPrefix ?? "",
    actorServiceAccountId: filters.actorServiceAccountId ?? "",
    actorType: filters.actorType ?? "",
    actorUserId: filters.actorUserId ?? "",
    correlationId: filters.correlationId ?? "",
    occurredBefore: filters.occurredBefore ?? "",
    occurredFrom: filters.occurredFrom ?? "",
    outcome: filters.outcome ?? "",
    requestId: filters.requestId ?? "",
    resourceId: filters.resourceId ?? "",
    resourceType: filters.resourceType ?? "",
    search: filters.search ?? "",
  };
  return normalizeAuditFilters(draft, surface);
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw toAuditApiError(result.response);
}

function projectPage(
  value: unknown,
  response: Response | undefined,
  surface: { kind: "platform" } | { kind: "tenant"; tenantId: string },
  query: AuditQuery,
  afterSequence: number,
): AuditPage {
  requireNoStore(response);
  if (!isRecord(value) || !exactKeys(value, pageKeys)) {
    throw projectionMismatch();
  }
  const items = value["items"];
  if (
    !Array.isArray(items) ||
    items.length > query.limit ||
    items.length > 100
  ) {
    throw projectionMismatch();
  }
  const projected: AuditEvent[] = [];
  const identifiers = new Set<string>();
  let previousSequence = afterSequence;
  let previous: AuditEvent | undefined;
  for (const item of items) {
    const event = projectEvent(item, surface);
    if (
      event.sequence <= previousSequence ||
      identifiers.has(event.id) ||
      !eventMatchesQuery(event, query)
    ) {
      throw projectionMismatch();
    }
    if (
      previous &&
      event.sequence === previous.sequence + 1 &&
      event.previousHash !== previous.eventHash
    ) {
      throw projectionMismatch();
    }
    projected.push(event);
    identifiers.add(event.id);
    previousSequence = event.sequence;
    previous = event;
  }

  const nextSequence = value["nextSequence"];
  if (nextSequence !== undefined) {
    if (
      !positiveSafeInteger(nextSequence) ||
      projected.length !== query.limit ||
      projected.at(-1)?.sequence !== nextSequence
    ) {
      throw projectionMismatch();
    }
    return { items: projected, nextSequence };
  }
  return { items: projected };
}

function eventMatchesQuery(event: AuditEvent, query: AuditQuery): boolean {
  const occurredAt = parseRfc3339Instant(event.occurredAt);
  const occurredFrom = query.occurredFrom
    ? parseRfc3339Instant(query.occurredFrom)
    : undefined;
  const occurredBefore = query.occurredBefore
    ? parseRfc3339Instant(query.occurredBefore)
    : undefined;
  if (
    occurredAt === undefined ||
    (occurredFrom !== undefined && occurredAt < occurredFrom) ||
    (occurredBefore !== undefined && occurredAt >= occurredBefore) ||
    (query.actorType !== undefined && event.actorType !== query.actorType) ||
    (query.actorUserId !== undefined &&
      event.actorUserId !== query.actorUserId) ||
    (query.actorServiceAccountId !== undefined &&
      event.actorServiceAccountId !== query.actorServiceAccountId) ||
    (query.actionPrefix !== undefined &&
      event.action !== query.actionPrefix &&
      !event.action.startsWith(`${query.actionPrefix}.`)) ||
    (query.resourceType !== undefined &&
      event.resourceType !== query.resourceType) ||
    (query.resourceId !== undefined && event.resourceId !== query.resourceId) ||
    (query.requestId !== undefined && event.requestId !== query.requestId) ||
    (query.correlationId !== undefined &&
      event.correlationId !== query.correlationId) ||
    (query.outcome !== undefined && event.outcome !== query.outcome)
  ) {
    return false;
  }
  if (query.search === undefined) return true;
  const search = query.search.toLocaleLowerCase("en-US");
  return (
    event.action.toLocaleLowerCase("en-US").includes(search) ||
    event.resourceType.toLocaleLowerCase("en-US").includes(search) ||
    event.reason?.toLocaleLowerCase("en-US").includes(search) === true
  );
}

function projectEvent(
  value: unknown,
  surface: { kind: "platform" } | { kind: "tenant"; tenantId: string },
): AuditEvent {
  if (!isRecord(value) || !exactKeys(value, eventKeys)) {
    throw projectionMismatch();
  }
  const id = value["id"];
  const tenantId = value["tenantId"];
  const sequence = value["sequence"];
  const occurredAt = value["occurredAt"];
  const actorType = value["actorType"];
  const actorUserId = value["actorUserId"];
  const actorServiceAccountId = value["actorServiceAccountId"];
  const impersonatedByUserId = value["impersonatedByUserId"];
  const action = value["action"];
  const resourceType = value["resourceType"];
  const resourceId = value["resourceId"];
  const requestId = value["requestId"];
  const correlationId = value["correlationId"];
  const ipAddress = value["ipAddress"];
  const userAgent = value["userAgent"];
  const authenticationMethod = value["authenticationMethod"];
  const outcome = value["outcome"];
  const reason = value["reason"];
  const previousHash = value["previousHash"];
  const eventHash = value["eventHash"];
  if (
    typeof id !== "string" ||
    !uuidV7Pattern.test(id) ||
    !positiveSafeInteger(sequence) ||
    typeof occurredAt !== "string" ||
    parseRfc3339Instant(occurredAt) === undefined ||
    !knownActorType(actorType) ||
    !knownOutcome(outcome) ||
    !validStableKey(action, 128) ||
    !validStableKey(resourceType, 128) ||
    !validOptionalUuid(actorUserId) ||
    !validOptionalUuid(actorServiceAccountId) ||
    !validOptionalUuid(impersonatedByUserId) ||
    !validOptionalUuid(resourceId) ||
    !validOptionalUuid(requestId) ||
    !validOptionalUuid(correlationId) ||
    !validOptionalIpAddress(ipAddress) ||
    !validOptionalText(userAgent, 1_024) ||
    !validOptionalText(reason, 1_000) ||
    !validOptionalAuthenticationMethod(authenticationMethod) ||
    typeof previousHash !== "string" ||
    !hashPattern.test(previousHash) ||
    typeof eventHash !== "string" ||
    !hashPattern.test(eventHash) ||
    (sequence === 1 && previousHash !== zeroHash)
  ) {
    throw projectionMismatch();
  }

  if (surface.kind === "tenant") {
    if (tenantId !== surface.tenantId) throw projectionMismatch();
  } else if (
    Object.hasOwn(value, "tenantId") ||
    actorServiceAccountId !== undefined ||
    impersonatedByUserId !== undefined
  ) {
    throw projectionMismatch();
  }

  if (
    (actorType === "user" && (!actorUserId || actorServiceAccountId)) ||
    (actorType === "service_account" &&
      (actorUserId ||
        (surface.kind === "tenant" && !actorServiceAccountId) ||
        impersonatedByUserId)) ||
    (actorType === "system" &&
      (actorUserId || actorServiceAccountId || impersonatedByUserId))
  ) {
    throw projectionMismatch();
  }

  return {
    id,
    ...(surface.kind === "tenant" ? { tenantId: surface.tenantId } : {}),
    sequence,
    occurredAt,
    actorType,
    ...(actorUserId === undefined ? {} : { actorUserId }),
    ...(actorServiceAccountId === undefined ? {} : { actorServiceAccountId }),
    ...(impersonatedByUserId === undefined ? {} : { impersonatedByUserId }),
    action,
    resourceType,
    ...(resourceId === undefined ? {} : { resourceId }),
    ...(requestId === undefined ? {} : { requestId }),
    ...(correlationId === undefined ? {} : { correlationId }),
    ...(ipAddress === undefined ? {} : { ipAddress }),
    ...(userAgent === undefined ? {} : { userAgent }),
    ...(authenticationMethod === undefined ? {} : { authenticationMethod }),
    outcome,
    ...(reason === undefined ? {} : { reason }),
    before: projectAuditDocument(value["before"], maximumDocumentBytes),
    after: projectAuditDocument(value["after"], maximumDocumentBytes),
    metadata: projectAuditDocument(value["metadata"], maximumMetadataBytes),
    previousHash,
    eventHash,
  };
}

function projectVerification(
  value: unknown,
  response: Response | undefined,
): AuditChainVerification {
  requireNoStore(response);
  if (!isRecord(value) || !exactKeys(value, verificationKeys)) {
    throw projectionMismatch();
  }
  const eventCount = value["eventCount"];
  const lastSequence = value["lastSequence"];
  const retainedThroughSequence = value["retainedThroughSequence"];
  const firstInvalidSequence = value["firstInvalidSequence"];
  const headValid = value["headValid"];
  const valid = value["valid"];
  const verifiedAt = value["verifiedAt"];
  if (
    !nonNegativeSafeInteger(eventCount) ||
    !nonNegativeSafeInteger(lastSequence) ||
    !nonNegativeSafeInteger(retainedThroughSequence) ||
    eventCount > lastSequence ||
    retainedThroughSequence > lastSequence ||
    (firstInvalidSequence !== undefined &&
      (!positiveSafeInteger(firstInvalidSequence) ||
        firstInvalidSequence > lastSequence)) ||
    typeof headValid !== "boolean" ||
    typeof valid !== "boolean" ||
    typeof verifiedAt !== "string" ||
    parseRfc3339Instant(verifiedAt) === undefined ||
    valid !==
      (headValid &&
        firstInvalidSequence === undefined &&
        eventCount === lastSequence)
  ) {
    throw projectionMismatch();
  }
  return {
    eventCount,
    lastSequence,
    retainedThroughSequence,
    ...(firstInvalidSequence === undefined ? {} : { firstInvalidSequence }),
    headValid,
    valid,
    verifiedAt,
  };
}

function projectAuditDocument(
  value: unknown,
  maximumBytes: number,
): AuditJsonDocument {
  if (!isRecord(value)) throw projectionMismatch();
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw projectionMismatch();
  }
  if (new TextEncoder().encode(encoded).length > maximumBytes) {
    throw projectionMismatch();
  }
  const counter = { nodes: 1 };
  return projectJsonObject(value, 1, counter);
}

function projectJsonObject(
  value: Record<string, unknown>,
  depth: number,
  counter: { nodes: number },
): AuditJsonDocument {
  const result: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (["__proto__", "constructor", "prototype"].includes(key)) {
      throw projectionMismatch();
    }
    const canonicalKey = canonicalJsonKey(key);
    if (
      prohibitedJsonKey(canonicalKey) ||
      !validSafeSensitiveValue(canonicalKey, child)
    ) {
      throw projectionMismatch();
    }
    result[key] = projectJsonValue(child, depth + 1, counter);
  }
  return result;
}

function projectJsonValue(
  value: unknown,
  depth: number,
  counter: { nodes: number },
): unknown {
  counter.nodes++;
  if (depth > maximumJsonDepth || counter.nodes > maximumJsonNodes) {
    throw projectionMismatch();
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    return value.map((item) => projectJsonValue(item, depth + 1, counter));
  }
  if (isRecord(value)) return projectJsonObject(value, depth, counter);
  throw projectionMismatch();
}

function prohibitedJsonKey(value: string): boolean {
  if (safeSensitiveKey(value)) return false;
  if (prohibitedKeys.has(value)) return true;
  return sensitiveKeyFragments.some((fragment) => value.includes(fragment));
}

function safeSensitiveKey(value: string): boolean {
  return (
    safeSensitiveBooleanKeys.has(value) ||
    safeSensitiveIdentifierKeys.has(value) ||
    safeSensitiveIntegerKeys.has(value) ||
    safeSensitiveKindKeys.has(value)
  );
}

function validSafeSensitiveValue(key: string, value: unknown): boolean {
  if (safeSensitiveBooleanKeys.has(key)) return typeof value === "boolean";
  if (safeSensitiveIdentifierKeys.has(key)) {
    return (
      value === null || (typeof value === "string" && uuidV7Pattern.test(value))
    );
  }
  if (safeSensitiveIntegerKeys.has(key)) {
    return nonNegativeSafeInteger(value);
  }
  if (safeSensitiveKindKeys.has(key)) {
    return typeof value === "string" && validStableKey(value, 64);
  }
  return true;
}

function canonicalJsonKey(value: string): string {
  return Array.from(value.toLowerCase())
    .filter((character) => /[\p{L}\p{N}]/u.test(character))
    .join("");
}

function requireTenant(tenantId: string): void {
  if (!isAuditTenantId(tenantId)) {
    throw new AuditApiError("A valid tenant context is required.");
  }
}

function requireCsrf(value: string): void {
  if (!value.trim() || value.length > 4_096 || hasForbiddenTextControl(value)) {
    throw new AuditApiError("Request integrity context is unavailable.");
  }
}

function requireNoStore(response: Response | undefined): void {
  const directives = response?.headers
    .get("Cache-Control")
    ?.toLowerCase()
    .split(",")
    .map((value) => value.trim());
  if (!directives?.includes("no-store")) {
    throw projectionMismatch(
      "The audit response did not carry its required no-store protection.",
    );
  }
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function validStableKey(value: unknown, maximum: number): value is string {
  return (
    typeof value === "string" &&
    value.length <= maximum &&
    stableKeyPattern.test(value)
  );
}

function validOptionalUuid(value: unknown): value is string | undefined {
  return (
    value === undefined ||
    (typeof value === "string" && uuidPattern.test(value))
  );
}

function validOptionalText(
  value: unknown,
  maximum: number,
): value is string | undefined {
  return (
    value === undefined ||
    (typeof value === "string" &&
      value.length > 0 &&
      Array.from(value).length <= maximum &&
      !hasForbiddenTextControl(value))
  );
}

function validOptionalAuthenticationMethod(
  value: unknown,
): value is string | undefined {
  return (
    value === undefined ||
    (typeof value === "string" && authenticationMethodPattern.test(value))
  );
}

function validOptionalIpAddress(value: unknown): value is string | undefined {
  if (value === undefined) return true;
  if (typeof value !== "string" || value.length === 0 || value.length > 64) {
    return false;
  }
  if (value.includes(":")) {
    try {
      return new URL(`http://[${value}]/`).hostname.length > 2;
    } catch {
      return false;
    }
  }
  const segments = value.split(".");
  return (
    segments.length === 4 &&
    segments.every(
      (segment) =>
        /^(?:0|[1-9]\d{0,2})$/u.test(segment) && Number(segment) <= 255,
    )
  );
}

function knownActorType(value: unknown): value is AuditActorType {
  return value === "user" || value === "service_account" || value === "system";
}

function knownOutcome(value: unknown): value is AuditOutcome {
  return value === "success" || value === "failure" || value === "denied";
}

function hasForbiddenTextControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      ((codePoint >= 0 && codePoint <= 8) ||
        codePoint === 11 ||
        codePoint === 12 ||
        (codePoint >= 14 && codePoint <= 31) ||
        codePoint === 127)
    ) {
      return true;
    }
  }
  return false;
}

function positiveSafeInteger(value: unknown): value is number {
  return nonNegativeSafeInteger(value) && value > 0;
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= maximumSequence
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function projectionMismatch(
  message = "The audit projection was not safe to display.",
): AuditApiError {
  return new AuditApiError(message, undefined, "projection_mismatch");
}

function toAuditApiError(response?: Response): AuditApiError {
  const status = response?.status;
  return new AuditApiError(fallbackForStatus(status), status);
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The audit filters were not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The server denied this audit operation.";
    case 429:
      return "Audit access is temporarily rate limited.";
    case 503:
      return "The protected audit reader is unavailable.";
    default:
      return "The audit request could not be completed.";
  }
}

export class AuditApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "AuditApiError";
  }
}
