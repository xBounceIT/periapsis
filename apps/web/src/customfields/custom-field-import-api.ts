import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import { isCanonicalUuidV7 } from "../lib/uuid-v7";
import {
  buildCustomFieldImportRequest,
  customFieldImportMaximumExpectedVersion,
  customFieldImportMaximumRevision,
  customFieldImportMaximumRows,
  type CustomFieldImportJobState,
  type CustomFieldImportJobView,
  type CustomFieldImportMode,
  type CustomFieldImportMutationView,
  type CustomFieldImportOutcome,
  type CustomFieldImportRequest,
  type CustomFieldImportResultPageView,
  type CustomFieldImportResultView,
} from "./custom-field-import-model";
import type { CustomFieldObjectType } from "./model";

export interface CustomFieldImportApi {
  request(input: {
    body: CustomFieldImportRequest;
    csrfToken: string;
    idempotencyKey: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldImportMutationView>;
  get(input: {
    jobId: string;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldImportJobView>;
  cancel(input: {
    csrfToken: string;
    expectedRevision: number;
    idempotencyKey: string;
    jobId: string;
    objectType: CustomFieldObjectType;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldImportMutationView>;
  listResults(input: {
    after?: number;
    jobId: string;
    objectType: CustomFieldObjectType;
    pageSize?: number;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomFieldImportResultPageView>;
}

export class CustomFieldImportApiError extends Error {
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  readonly status: number | undefined;

  constructor(
    message: string,
    status?: number,
    code?: string,
    requestId?: string,
  ) {
    super(message);
    this.name = "CustomFieldImportApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const etagPattern = /^"v([1-9][0-9]*)"$/u;
const fieldKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const fieldErrorCodes = new Set([
  "unknown",
  "visibility_denied",
  "edit_denied",
  "invalid_context",
  "malformed",
  "required",
  "null_not_allowed",
  "empty_not_allowed",
  "invalid_text",
  "invalid_integer",
  "invalid_decimal",
  "invalid_boolean",
  "invalid_date",
  "invalid_datetime",
  "invalid_option",
  "invalid_options",
  "invalid_url",
  "invalid_email",
  "invalid_ip",
  "invalid_cidr",
  "invalid_reference",
  "invalid_json",
  "invalid_type",
]);

export const customFieldImportApi: CustomFieldImportApi = {
  async request({ body, csrfToken, idempotencyKey, signal, tenantId }) {
    requireMutationContext(tenantId, csrfToken, idempotencyKey);
    const canonicalBody = buildCustomFieldImportRequest(body);
    const collectionPath = collectionPathFor(tenantId);
    const response = await sessionAwareFetch(collectionPath, {
      method: "POST",
      headers: mutationHeaders(csrfToken, idempotencyKey),
      body: JSON.stringify(canonicalBody),
      ...(signal ? { signal } : {}),
    });
    const payload = await requireJson(response, 202);
    const projected = projectMutation(
      payload,
      response,
      tenantId,
      body.objectType,
    );
    validateRequestReceipt(projected.job, canonicalBody);
    if (
      response.headers.get("Location") !==
      `${collectionPath}/${projected.job.id}`
    ) {
      throw projectionMismatch(
        "The custom-field import location was not canonical.",
      );
    }
    return projected;
  },

  async get({ jobId, objectType, signal, tenantId }) {
    requireCoordinates(tenantId, jobId, objectType);
    const response = await sessionAwareFetch(
      withObjectType(`${collectionPathFor(tenantId)}/${jobId}`, objectType),
      {
        method: "GET",
        headers: { Accept: "application/json" },
        ...(signal ? { signal } : {}),
      },
    );
    const payload = await requireJson(response, 200);
    const job = projectJob(payload, tenantId, objectType, jobId);
    requireVersionEtag(response, job.revision);
    return job;
  },

  async cancel({
    csrfToken,
    expectedRevision,
    idempotencyKey,
    jobId,
    objectType,
    signal,
    tenantId,
  }) {
    requireMutationContext(tenantId, csrfToken, idempotencyKey);
    requireCoordinates(tenantId, jobId, objectType);
    requireJobRevision(expectedRevision);
    const response = await sessionAwareFetch(
      `${collectionPathFor(tenantId)}/${jobId}/cancel`,
      {
        method: "POST",
        headers: {
          ...mutationHeaders(csrfToken, idempotencyKey),
          "If-Match": `"v${expectedRevision}"`,
        },
        body: JSON.stringify({ objectType, expectedRevision }),
        ...(signal ? { signal } : {}),
      },
    );
    const payload = await requireJson(response, 200);
    const projected = projectMutation(
      payload,
      response,
      tenantId,
      objectType,
      jobId,
    );
    if (
      projected.job.revision !== expectedRevision + 1 ||
      (projected.job.state !== "cancellation_requested" &&
        projected.job.state !== "cancelled")
    ) {
      throw projectionMismatch(
        "The custom-field import cancellation receipt was not canonical.",
      );
    }
    return projected;
  },

  async listResults({
    after,
    jobId,
    objectType,
    pageSize = 100,
    signal,
    tenantId,
  }) {
    requireCoordinates(tenantId, jobId, objectType);
    if (
      !Number.isSafeInteger(pageSize) ||
      pageSize < 1 ||
      pageSize > 100 ||
      (after !== undefined &&
        (!Number.isSafeInteger(after) || after < 1 || after > 10_000))
    ) {
      throw projectionMismatch(
        "The custom-field import result page request was not canonical.",
      );
    }
    const url = new URL(
      `${collectionPathFor(tenantId)}/${jobId}/results`,
      globalThis.location.origin,
    );
    url.searchParams.set("objectType", objectType);
    url.searchParams.set("pageSize", String(pageSize));
    if (after !== undefined) url.searchParams.set("after", String(after));
    const response = await sessionAwareFetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      ...(signal ? { signal } : {}),
    });
    const payload = await requireJson(response, 200);
    return projectResultPage(payload, pageSize, after);
  },
};

export function describeCustomFieldImportError(error: unknown): string {
  if (error instanceof CustomFieldImportApiError) return error.message;
  if (error instanceof TypeError) return error.message;
  return "The custom-field import operation could not be completed.";
}

function validateRequestReceipt(
  job: CustomFieldImportJobView,
  request: CustomFieldImportRequest,
): void {
  const requestedAt = parseRfc3339Instant(job.requestedAt);
  const updatedAt = parseRfc3339Instant(job.updatedAt);
  const availableAt = parseRfc3339Instant(job.availableAt);
  const expiresAt = parseRfc3339Instant(job.expiresAt);
  if (
    job.objectType !== request.objectType ||
    job.mode !== request.mode ||
    job.state !== "pending" ||
    job.revision !== 1 ||
    job.attempts !== 0 ||
    job.activeAttempt ||
    job.terminalAt !== undefined ||
    job.progress.total !== request.rows.length ||
    job.progress.processed !== 0 ||
    requestedAt === undefined ||
    updatedAt !== requestedAt ||
    availableAt !== requestedAt ||
    expiresAt === undefined ||
    expiresAt - requestedAt !==
      BigInt(request.retentionSeconds) * 1_000_000_000n
  ) {
    throw projectionMismatch(
      "The custom-field import receipt did not match the reviewed request.",
    );
  }
}

function projectMutation(
  value: unknown,
  response: Response,
  tenantId: string,
  objectType: CustomFieldObjectType,
  expectedJobId?: string,
): CustomFieldImportMutationView {
  const record = exactRecord(value, ["job", "replayed"], ["job", "replayed"]);
  if (typeof record["replayed"] !== "boolean") throw projectionMismatch();
  const job = projectJob(record["job"], tenantId, objectType, expectedJobId);
  const etag = requireVersionEtag(response, job.revision);
  requireIdempotentReplay(response, record["replayed"]);
  return { job, replayed: record["replayed"], etag };
}

function projectJob(
  value: unknown,
  tenantId: string,
  objectType: CustomFieldObjectType,
  expectedJobId?: string,
): CustomFieldImportJobView {
  const record = exactRecord(
    value,
    [
      "activeAttempt",
      "attempts",
      "availableAt",
      "expiresAt",
      "id",
      "mode",
      "objectType",
      "ownerMembershipId",
      "progress",
      "requestedAt",
      "requesterUserId",
      "revision",
      "state",
      "tenantId",
      "terminalAt",
      "updatedAt",
    ],
    [
      "activeAttempt",
      "attempts",
      "availableAt",
      "expiresAt",
      "id",
      "mode",
      "objectType",
      "ownerMembershipId",
      "progress",
      "requestedAt",
      "requesterUserId",
      "revision",
      "state",
      "tenantId",
      "updatedAt",
    ],
  );
  if (
    record["tenantId"] !== tenantId ||
    record["objectType"] !== objectType ||
    !isCanonicalUuidV7(record["id"]) ||
    (expectedJobId !== undefined && record["id"] !== expectedJobId) ||
    !isCanonicalUuidV7(record["requesterUserId"]) ||
    !isCanonicalUuidV7(record["ownerMembershipId"]) ||
    typeof record["activeAttempt"] !== "boolean"
  ) {
    throw projectionMismatch();
  }
  const mode = requireImportMode(record["mode"]);
  const state = requireJobState(record["state"]);
  const revision = requireJobRevision(record["revision"]);
  const attempts = requireBoundedCount(record["attempts"], 0, 5);
  const progress = projectProgress(record["progress"]);
  const requestedAt = projectInstant(record["requestedAt"]);
  const updatedAt = projectInstant(record["updatedAt"]);
  const availableAt = projectInstant(record["availableAt"]);
  const expiresAt = projectInstant(record["expiresAt"]);
  const terminalAt =
    record["terminalAt"] === undefined
      ? undefined
      : projectInstant(record["terminalAt"]);
  const terminal =
    state === "completed" ||
    state === "failed" ||
    state === "cancelled" ||
    state === "authorization_revoked" ||
    state === "expired";
  const active = state === "running" || state === "cancellation_requested";
  if (
    updatedAt.value < requestedAt.value ||
    availableAt.value < requestedAt.value ||
    availableAt.value > expiresAt.value ||
    expiresAt.value <= requestedAt.value ||
    terminal !== (terminalAt !== undefined) ||
    (terminalAt !== undefined && terminalAt.value !== updatedAt.value) ||
    record["activeAttempt"] !== active ||
    (state === "pending" &&
      (revision !== 1 ||
        attempts !== 0 ||
        progress.processed !== 0 ||
        updatedAt.value !== requestedAt.value ||
        availableAt.value !== requestedAt.value)) ||
    (terminal && progress.processed !== progress.total) ||
    (state === "completed" &&
      progress.cancelled +
        progress.authorizationRevoked +
        progress.expired +
        progress.internalFailure !==
        0) ||
    (state === "failed" && progress.internalFailure === 0) ||
    (state === "cancelled" && progress.cancelled === 0) ||
    (state === "authorization_revoked" &&
      progress.authorizationRevoked === 0) ||
    (state === "expired" && progress.expired === 0)
  ) {
    throw projectionMismatch();
  }
  return {
    id: record["id"],
    tenantId,
    requesterUserId: record["requesterUserId"],
    ownerMembershipId: record["ownerMembershipId"],
    objectType,
    mode,
    state,
    revision,
    attempts,
    progress,
    requestedAt: requestedAt.text,
    updatedAt: updatedAt.text,
    availableAt: availableAt.text,
    expiresAt: expiresAt.text,
    activeAttempt: record["activeAttempt"],
    ...(terminalAt ? { terminalAt: terminalAt.text } : {}),
  };
}

function projectProgress(value: unknown): CustomFieldImportJobView["progress"] {
  const keys = [
    "authorizationDenied",
    "authorizationRevoked",
    "cancelled",
    "expired",
    "internalFailure",
    "noChange",
    "notFoundOrHidden",
    "processed",
    "rejected",
    "succeeded",
    "total",
    "versionConflict",
  ] as const;
  const record = exactRecord(value, keys, keys);
  const progress: CustomFieldImportJobView["progress"] = {
    authorizationDenied: progressCount(record, "authorizationDenied"),
    authorizationRevoked: progressCount(record, "authorizationRevoked"),
    cancelled: progressCount(record, "cancelled"),
    expired: progressCount(record, "expired"),
    internalFailure: progressCount(record, "internalFailure"),
    noChange: progressCount(record, "noChange"),
    notFoundOrHidden: progressCount(record, "notFoundOrHidden"),
    processed: progressCount(record, "processed"),
    rejected: progressCount(record, "rejected"),
    succeeded: progressCount(record, "succeeded"),
    total: progressCount(record, "total"),
    versionConflict: progressCount(record, "versionConflict"),
  };
  const classified =
    progress.succeeded +
    progress.noChange +
    progress.versionConflict +
    progress.notFoundOrHidden +
    progress.authorizationDenied +
    progress.rejected +
    progress.cancelled +
    progress.authorizationRevoked +
    progress.expired +
    progress.internalFailure;
  if (
    progress.total < 1 ||
    progress.processed !== classified ||
    progress.processed > progress.total
  ) {
    throw projectionMismatch();
  }
  return progress;
}

function progressCount(record: Record<string, unknown>, key: string): number {
  return requireBoundedCount(record[key], 0, customFieldImportMaximumRows);
}

function projectResultPage(
  value: unknown,
  pageSize: number,
  after?: number,
): CustomFieldImportResultPageView {
  const record = exactRecord(value, ["items", "nextAfter"], ["items"]);
  if (!Array.isArray(record["items"]) || record["items"].length > pageSize) {
    throw projectionMismatch();
  }
  let previous = after ?? 0;
  const items = record["items"].map((item): CustomFieldImportResultView => {
    const projected = projectResult(item);
    if (projected.sequence !== previous + 1) throw projectionMismatch();
    previous = projected.sequence;
    return projected;
  });
  const nextAfter = record["nextAfter"];
  if (
    nextAfter !== undefined &&
    (!Number.isSafeInteger(nextAfter) ||
      Number(nextAfter) < 1 ||
      Number(nextAfter) > customFieldImportMaximumRows ||
      Number(nextAfter) !== previous ||
      items.length !== pageSize)
  ) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(nextAfter === undefined ? {} : { nextAfter: Number(nextAfter) }),
  };
}

function projectResult(value: unknown): CustomFieldImportResultView {
  const record = exactRecord(
    value,
    [
      "expectedVersion",
      "fieldErrors",
      "outcome",
      "recordedAt",
      "resultingVersion",
      "sequence",
      "targetId",
    ],
    [
      "expectedVersion",
      "fieldErrors",
      "outcome",
      "recordedAt",
      "resultingVersion",
      "sequence",
      "targetId",
    ],
  );
  if (
    !isCanonicalUuidV7(record["targetId"]) ||
    !Array.isArray(record["fieldErrors"]) ||
    record["fieldErrors"].length > 512
  ) {
    throw projectionMismatch();
  }
  const sequence = requireBoundedCount(
    record["sequence"],
    1,
    customFieldImportMaximumRows,
  );
  const outcome = requireOutcome(record["outcome"]);
  const expectedVersion = requireResourceVersion(record["expectedVersion"]);
  const resultingVersion = requireBoundedCount(
    record["resultingVersion"],
    0,
    Number.MAX_SAFE_INTEGER,
  );
  let previousField = "";
  let previousCode = "";
  const fieldErrors = record["fieldErrors"].map((item) => {
    const error = exactRecord(item, ["code", "field"], ["code", "field"]);
    if (
      typeof error["field"] !== "string" ||
      !fieldKeyPattern.test(error["field"]) ||
      typeof error["code"] !== "string" ||
      !fieldErrorCodes.has(error["code"]) ||
      error["field"] < previousField ||
      (error["field"] === previousField && error["code"] <= previousCode)
    ) {
      throw projectionMismatch();
    }
    previousField = error["field"];
    previousCode = error["code"];
    return { field: error["field"], code: error["code"] };
  });
  const successful =
    outcome === "dry_run_valid" ||
    outcome === "committed" ||
    outcome === "no_change";
  const expectedResultingVersion =
    outcome === "committed"
      ? expectedVersion + 1
      : outcome === "dry_run_valid" || outcome === "no_change"
        ? expectedVersion
        : 0;
  if (
    successful !== resultingVersion > 0 ||
    resultingVersion !== expectedResultingVersion ||
    (outcome === "validation_failed") !== fieldErrors.length > 0
  ) {
    throw projectionMismatch();
  }
  return {
    sequence,
    targetId: record["targetId"],
    expectedVersion,
    outcome,
    resultingVersion,
    fieldErrors,
    recordedAt: projectInstant(record["recordedAt"]).text,
  };
}

async function requireJson(
  response: Response,
  expectedStatus: number,
): Promise<unknown> {
  if (response.status !== expectedStatus) {
    if (!hasNoStore(response)) {
      throw projectionMismatch(
        "The custom-field import error response was not safe to display.",
      );
    }
    throw await responseError(response);
  }
  const cacheControl = response.headers
    .get("Cache-Control")
    ?.split(",")
    .map((item) => item.trim().toLowerCase());
  if (
    cacheControl?.length !== 2 ||
    !cacheControl.includes("private") ||
    !cacheControl.includes("no-store")
  ) {
    throw projectionMismatch(
      "The custom-field import response was not private and canonical.",
    );
  }
  const contentType = response.headers.get("Content-Type")?.toLowerCase();
  if (!contentType?.startsWith("application/json")) throw projectionMismatch();
  try {
    return (await response.json()) as unknown;
  } catch {
    throw projectionMismatch();
  }
}

function hasNoStore(response: Response): boolean {
  return (
    response.headers
      .get("Cache-Control")
      ?.split(",")
      .some((item) => item.trim().toLowerCase() === "no-store") === true
  );
}

async function responseError(
  response: Response,
): Promise<CustomFieldImportApiError> {
  let problem: Record<string, unknown> | undefined;
  try {
    const decoded = (await response.json()) as unknown;
    if (isRecord(decoded)) problem = decoded;
  } catch {
    // A malformed error stays generic and does not become displayable data.
  }
  const detail =
    typeof problem?.["detail"] === "string" &&
    !hasControlCharacter(problem["detail"])
      ? problem["detail"]
      : undefined;
  const title =
    typeof problem?.["title"] === "string" &&
    !hasControlCharacter(problem["title"])
      ? problem["title"]
      : undefined;
  const code =
    typeof problem?.["code"] === "string" ? problem["code"] : undefined;
  const requestId =
    typeof problem?.["requestId"] === "string"
      ? problem["requestId"]
      : undefined;
  return new CustomFieldImportApiError(
    (detail ?? title ?? statusMessage(response.status)).slice(0, 320),
    response.status,
    code,
    requestId,
  );
}

function requireVersionEtag(response: Response, revision: number): string {
  const etag = response.headers.get("ETag") ?? "";
  const match = etagPattern.exec(etag);
  if (!match || Number(match[1]) !== revision) throw projectionMismatch();
  return etag;
}

function requireIdempotentReplay(response: Response, replayed: boolean): void {
  if (response.headers.get("X-Idempotent-Replay") !== String(replayed)) {
    throw projectionMismatch(
      "The custom-field import replay receipt was not canonical.",
    );
  }
}

function requireCoordinates(
  tenantId: string,
  jobId: string,
  objectType: CustomFieldObjectType,
): void {
  if (!isCanonicalUuidV7(tenantId) || !isCanonicalUuidV7(jobId)) {
    throw projectionMismatch("A canonical UUIDv7 coordinate is required.");
  }
  requireObjectType(objectType);
}

function requireMutationContext(
  tenantId: string,
  csrfToken: string,
  idempotencyKey: string,
): void {
  if (
    !isCanonicalUuidV7(tenantId) ||
    csrfToken.trim() === "" ||
    csrfToken.length > 4_096 ||
    hasControlCharacter(csrfToken) ||
    !idempotencyKeyPattern.test(idempotencyKey)
  ) {
    throw projectionMismatch("The mutation context was not canonical.");
  }
}

function mutationHeaders(
  csrfToken: string,
  idempotencyKey: string,
): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/json",
    "Idempotency-Key": idempotencyKey,
    "X-CSRF-Token": csrfToken,
  };
}

function collectionPathFor(tenantId: string): string {
  return `/api/v1/tenants/${tenantId}/custom-field-imports`;
}

function withObjectType(
  path: string,
  objectType: CustomFieldObjectType,
): string {
  const url = new URL(path, globalThis.location.origin);
  url.searchParams.set("objectType", objectType);
  return url.href;
}

function requireObjectType(value: unknown): CustomFieldObjectType {
  if (value !== "alert" && value !== "case") throw projectionMismatch();
  return value;
}

function requireImportMode(value: unknown): CustomFieldImportMode {
  if (value !== "dry_run" && value !== "commit") throw projectionMismatch();
  return value;
}

function requireJobState(value: unknown): CustomFieldImportJobState {
  if (
    value !== "pending" &&
    value !== "running" &&
    value !== "cancellation_requested" &&
    value !== "completed" &&
    value !== "failed" &&
    value !== "cancelled" &&
    value !== "authorization_revoked" &&
    value !== "expired"
  ) {
    throw projectionMismatch();
  }
  return value;
}

function requireOutcome(value: unknown): CustomFieldImportOutcome {
  if (
    value !== "dry_run_valid" &&
    value !== "committed" &&
    value !== "no_change" &&
    value !== "validation_failed" &&
    value !== "definition_changed" &&
    value !== "version_conflict" &&
    value !== "not_found_or_hidden" &&
    value !== "authorization_denied" &&
    value !== "cancelled" &&
    value !== "authorization_revoked" &&
    value !== "expired" &&
    value !== "internal_failure"
  ) {
    throw projectionMismatch();
  }
  return value;
}

function requireResourceVersion(value: unknown): number {
  return requireBoundedCount(value, 1, customFieldImportMaximumExpectedVersion);
}

function requireJobRevision(value: unknown): number {
  return requireBoundedCount(value, 1, customFieldImportMaximumRevision);
}

function requireBoundedCount(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectInstant(value: unknown): { text: string; value: bigint } {
  if (typeof value !== "string") throw projectionMismatch();
  const instant = parseRfc3339Instant(value);
  if (instant === undefined) throw projectionMismatch();
  return { text: value, value: instant };
}

function exactRecord(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> {
  if (!isRecord(value)) throw projectionMismatch();
  const allowedSet = new Set(allowed);
  if (
    Object.keys(value).some((key) => !allowedSet.has(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  ) {
    throw projectionMismatch();
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const point = character.codePointAt(0);
    if (
      point !== undefined &&
      (point <= 0x1f ||
        (point >= 0x7f && point <= 0x9f) ||
        (point >= 0x202a && point <= 0x202e) ||
        (point >= 0x2066 && point <= 0x2069))
    ) {
      return true;
    }
  }
  return false;
}

function statusMessage(status: number): string {
  switch (status) {
    case 401:
      return "Sign in again before retrying this import.";
    case 403:
      return "Your current tenant authority does not permit this import.";
    case 404:
      return "The import receipt is no longer available.";
    case 409:
      return "This import request conflicts with an existing receipt.";
    case 412:
    case 428:
      return "The import receipt changed. Refresh it before retrying.";
    case 413:
      return "The import request exceeds the supported payload size.";
    case 422:
      return "The import request contains invalid rows or field values.";
    default:
      return "The custom-field import operation could not be completed.";
  }
}

function projectionMismatch(
  message = "The custom-field import response was not safe to display.",
): CustomFieldImportApiError {
  return new CustomFieldImportApiError(
    message,
    undefined,
    "projection_mismatch",
  );
}
