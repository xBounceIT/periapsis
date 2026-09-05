import {
  cancelPlatformAuditExport,
  cancelTenantAuditExport,
  createPlatformAuditExport,
  createTenantAuditExport,
  downloadPlatformAuditExport,
  downloadTenantAuditExport,
  getPlatformAuditExport,
  getPlatformAuditRetention,
  getTenantAuditExport,
  getTenantAuditRetention,
  placePlatformAuditLegalHold,
  placeTenantAuditLegalHold,
  releasePlatformAuditLegalHold,
  releaseTenantAuditLegalHold,
  updatePlatformAuditRetention,
  updateTenantAuditRetention,
  type AuditExportFilter,
  type AuditExportJob,
  type AuditExportMutationResult,
  type AuditLegalHold,
  type AuditLegalHoldMutationResult,
  type AuditRetentionMutationResult,
  type AuditRetentionState,
} from "@periapsis/contracts";

import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import { AuditApiError } from "./audit-api";
import { isAuditTenantId, type AuditQuery } from "./model";

export type AuditOperationsScope =
  { kind: "platform" } | { kind: "tenant"; tenantId: string };

export interface AuditOperationsApi {
  createExport(input: {
    csrfToken: string;
    filters: AuditQuery;
    idempotencyKey: string;
    reason: string;
    retentionSeconds: number;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditExportMutationResult>;
  getExport(input: {
    exportId: string;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditExportJob>;
  cancelExport(input: {
    csrfToken: string;
    expectedRevision: number;
    exportId: string;
    idempotencyKey: string;
    reason: string;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditExportMutationResult>;
  downloadExport(input: {
    exportId: string;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<{ blob: Blob; filename: string }>;
  getRetention(input: {
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditRetentionState>;
  updateRetention(input: {
    csrfToken: string;
    expectedRevision: number;
    idempotencyKey: string;
    reason: string;
    retentionDays: number;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditRetentionMutationResult>;
  placeLegalHold(input: {
    csrfToken: string;
    idempotencyKey: string;
    reason: string;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditLegalHoldMutationResult>;
  releaseLegalHold(input: {
    csrfToken: string;
    expectedRevision: 1;
    holdId: string;
    idempotencyKey: string;
    reason: string;
    scope: AuditOperationsScope;
    signal?: AbortSignal;
  }): Promise<AuditLegalHoldMutationResult>;
}

interface GeneratedResult<T> {
  data?: T;
  error?: unknown;
  response?: Response;
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const idempotencyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const visibleReasonPattern = /^[\x20-\x7e]{1,500}$/u;
const reasonSensitivePattern =
  /(?:password|secret|token|credential|assertion|cookie|private[ _-]?key|api[ _-]?key|@)/iu;
const terminalStates = new Set([
  "succeeded",
  "failed",
  "cancelled",
  "authorization_revoked",
  "expired",
]);
const exportStates = new Set([
  "pending",
  "running",
  "cancellation_requested",
  ...terminalStates,
]);
const failureCodes = new Set([
  "none",
  "transient_storage",
  "transient_database",
  "authorization_revoked",
  "output_limit",
  "lease_expired",
  "expired",
  "internal",
]);
const filterKeys = new Set([
  "occurredFrom",
  "occurredBefore",
  "actorType",
  "actorUserId",
  "actorServiceAccountId",
  "actionPrefix",
  "resourceType",
  "resourceId",
  "requestId",
  "correlationId",
  "outcome",
  "search",
]);
const jobKeys = new Set([
  "id",
  "stream",
  "tenantId",
  "requesterUserId",
  "filter",
  "filterSha256",
  "projectionVersion",
  "format",
  "state",
  "revision",
  "attempts",
  "maximumAttempts",
  "failureCode",
  "requestedAt",
  "updatedAt",
  "availableAt",
  "expiresAt",
  "terminalAt",
  "artifact",
]);

const requestDefaults = {
  baseUrl: globalThis.location.origin,
  cache: "no-store" as const,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

export const auditOperationsApi: AuditOperationsApi = {
  async createExport(input) {
    requireMutation(input);
    if (
      !Number.isSafeInteger(input.retentionSeconds) ||
      input.retentionSeconds < 900 ||
      input.retentionSeconds > 604_800
    ) {
      throw invalid(
        "Choose an artifact lifetime between 15 minutes and 7 days.",
      );
    }
    const filter = exportFilter(input.filters, input.scope.kind);
    const options = {
      ...requestDefaults,
      body: { filter, retentionSeconds: input.retentionSeconds },
      headers: mutationHeaders(input),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await createTenantAuditExport({
            ...options,
            path: { tenantId: requireTenant(input.scope.tenantId) },
          })
        : await createPlatformAuditExport(options);
    const mutation = projectMutation(unwrap(result), input.scope);
    const requestedAt = instant(mutation.job.requestedAt).value;
    const expiresAt = instant(mutation.job.expiresAt).value;
    if (
      JSON.stringify(mutation.job.filter) !== JSON.stringify(filter) ||
      expiresAt - requestedAt !==
        BigInt(input.retentionSeconds) * 1_000_000_000n
    ) {
      throw projectionMismatch(
        "The export receipt did not bind the requested snapshot.",
      );
    }
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, mutation.job.revision);
    return mutation;
  },

  async getExport(input) {
    requireExportId(input.exportId);
    const options = {
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await getTenantAuditExport({
            ...options,
            path: {
              exportId: input.exportId,
              tenantId: requireTenant(input.scope.tenantId),
            },
          })
        : await getPlatformAuditExport({
            ...options,
            path: { exportId: input.exportId },
          });
    const job = projectJob(unwrap(result), input.scope, input.exportId);
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, job.revision);
    return job;
  },

  async cancelExport(input) {
    requireMutation(input);
    requireExportId(input.exportId);
    requireRevision(input.expectedRevision);
    const options = {
      ...requestDefaults,
      body: { expectedRevision: input.expectedRevision },
      headers: {
        ...mutationHeaders(input),
        "If-Match": versionEtag(input.expectedRevision),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await cancelTenantAuditExport({
            ...options,
            path: {
              exportId: input.exportId,
              tenantId: requireTenant(input.scope.tenantId),
            },
          })
        : await cancelPlatformAuditExport({
            ...options,
            path: { exportId: input.exportId },
          });
    const mutation = projectMutation(
      unwrap(result),
      input.scope,
      input.exportId,
    );
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, mutation.job.revision);
    return mutation;
  },

  async downloadExport(input) {
    requireExportId(input.exportId);
    const options = {
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await downloadTenantAuditExport({
            ...options,
            path: {
              exportId: input.exportId,
              tenantId: requireTenant(input.scope.tenantId),
            },
          })
        : await downloadPlatformAuditExport({
            ...options,
            path: { exportId: input.exportId },
          });
    const value = unwrap(result);
    requireProtectedResponse(result.response);
    const contentType = result.response?.headers.get("Content-Type") ?? "";
    const disposition =
      result.response?.headers.get("Content-Disposition") ?? "";
    if (
      !(value instanceof Blob) ||
      !contentType.toLowerCase().startsWith("application/x-ndjson") ||
      result.response?.headers.has("Location") ||
      !/^attachment; filename="audit-(?:tenant|platform)-[0-9a-f-]+\.jsonl"$/u.test(
        disposition,
      )
    ) {
      throw projectionMismatch(
        "The audit download was not a manifest-bound JSONL artifact.",
      );
    }
    const declaredSize = Number(result.response?.headers.get("Content-Length"));
    if (!Number.isSafeInteger(declaredSize) || declaredSize !== value.size) {
      throw projectionMismatch(
        "The audit download size did not match its manifest.",
      );
    }
    return {
      blob: value,
      filename: disposition.slice('attachment; filename="'.length, -1),
    };
  },

  async getRetention(input) {
    const options = {
      ...requestDefaults,
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await getTenantAuditRetention({
            ...options,
            path: { tenantId: requireTenant(input.scope.tenantId) },
          })
        : await getPlatformAuditRetention(options);
    const state = projectRetention(unwrap(result), input.scope);
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, state.policy.revision);
    return state;
  },

  async updateRetention(input) {
    requireMutation(input);
    requireRevision(input.expectedRevision);
    if (
      !Number.isSafeInteger(input.retentionDays) ||
      input.retentionDays < 30 ||
      input.retentionDays > 3_650
    ) {
      throw invalid("Choose retention between 30 days and 10 years.");
    }
    const options = {
      ...requestDefaults,
      body: {
        expectedRevision: input.expectedRevision,
        retentionDays: input.retentionDays,
      },
      headers: {
        ...mutationHeaders(input),
        "If-Match": versionEtag(input.expectedRevision),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await updateTenantAuditRetention({
            ...options,
            path: { tenantId: requireTenant(input.scope.tenantId) },
          })
        : await updatePlatformAuditRetention(options);
    const mutation = projectRetentionMutation(unwrap(result), input.scope);
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, mutation.state.policy.revision);
    return mutation;
  },

  async placeLegalHold(input) {
    requireMutation(input);
    const options = {
      ...requestDefaults,
      headers: mutationHeaders(input),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await placeTenantAuditLegalHold({
            ...options,
            path: { tenantId: requireTenant(input.scope.tenantId) },
          })
        : await placePlatformAuditLegalHold(options);
    const mutation = projectHoldMutation(unwrap(result));
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, mutation.hold.revision);
    return mutation;
  },

  async releaseLegalHold(input) {
    requireMutation(input);
    requireUuid(input.holdId, "legal hold");
    if (input.expectedRevision !== 1) {
      throw invalid("The legal hold revision is invalid.");
    }
    const options = {
      ...requestDefaults,
      body: { expectedRevision: 1 as const },
      headers: {
        ...mutationHeaders(input),
        "If-Match": versionEtag(input.expectedRevision),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.scope.kind === "tenant"
        ? await releaseTenantAuditLegalHold({
            ...options,
            path: {
              holdId: input.holdId,
              tenantId: requireTenant(input.scope.tenantId),
            },
          })
        : await releasePlatformAuditLegalHold({
            ...options,
            path: { holdId: input.holdId },
          });
    const mutation = projectHoldMutation(unwrap(result));
    requireProtectedResponse(result.response);
    requireVersionEtag(result.response, mutation.hold.revision);
    return mutation;
  },
};

function exportFilter(
  filters: AuditQuery,
  surface: "tenant" | "platform",
): AuditExportFilter {
  const result: AuditExportFilter = {
    ...(filters.occurredFrom ? { occurredFrom: filters.occurredFrom } : {}),
    ...(filters.occurredBefore
      ? { occurredBefore: filters.occurredBefore }
      : {}),
    ...(filters.actorType ? { actorType: filters.actorType } : {}),
    ...(filters.actorUserId ? { actorUserId: filters.actorUserId } : {}),
    ...(surface === "tenant" && filters.actorServiceAccountId
      ? { actorServiceAccountId: filters.actorServiceAccountId }
      : {}),
    ...(filters.actionPrefix ? { actionPrefix: filters.actionPrefix } : {}),
    ...(filters.resourceType ? { resourceType: filters.resourceType } : {}),
    ...(filters.resourceId ? { resourceId: filters.resourceId } : {}),
    ...(filters.requestId ? { requestId: filters.requestId } : {}),
    ...(filters.correlationId ? { correlationId: filters.correlationId } : {}),
    ...(filters.outcome ? { outcome: filters.outcome } : {}),
    ...(filters.search ? { search: filters.search } : {}),
  };
  return result;
}

function projectMutation(
  value: unknown,
  scope: AuditOperationsScope,
  expectedId?: string,
): AuditExportMutationResult {
  const record = exactRecord(value, new Set(["job", "replayed"]));
  if (typeof record["replayed"] !== "boolean") throw projectionMismatch();
  return {
    job: projectJob(record["job"], scope, expectedId),
    replayed: record["replayed"],
  };
}

function projectJob(
  value: unknown,
  scope: AuditOperationsScope,
  expectedId?: string,
): AuditExportJob {
  const record = exactRecord(value, jobKeys);
  const id = requireUuid(record["id"], "export");
  if (expectedId !== undefined && id !== expectedId) throw projectionMismatch();
  const requesterUserId = requireUuid(record["requesterUserId"], "requester");
  const stream = auditStream(record["stream"]);
  const tenantId = record["tenantId"];
  if (
    stream !== scope.kind ||
    (scope.kind === "tenant" && tenantId !== scope.tenantId) ||
    (scope.kind === "platform" && tenantId !== undefined)
  ) {
    throw projectionMismatch(
      "The audit export crossed its authorization boundary.",
    );
  }
  const state = auditExportState(record["state"]);
  const failureCode = auditFailureCode(record["failureCode"]);
  const revision = positiveInteger(record["revision"]);
  const maximumAttempts = boundedInteger(record["maximumAttempts"], 1, 10);
  const attempts = boundedInteger(record["attempts"], 0, maximumAttempts);
  if (
    record["projectionVersion"] !== 1 ||
    record["format"] !== "jsonl" ||
    !sha256Pattern.test(String(record["filterSha256"])) ||
    (failureCode === "none") !==
      ["pending", "running", "cancellation_requested", "succeeded"].includes(
        state,
      )
  ) {
    throw projectionMismatch();
  }
  const filter = projectFilter(record["filter"], scope.kind);
  const requestedAt = instant(record["requestedAt"]);
  const updatedAt = instant(record["updatedAt"]);
  const availableAt = instant(record["availableAt"]);
  const expiresAt = instant(record["expiresAt"]);
  const terminalAt =
    record["terminalAt"] === undefined
      ? undefined
      : instant(record["terminalAt"]);
  const terminal = terminalStates.has(state);
  if (
    updatedAt.value < requestedAt.value ||
    availableAt.value < requestedAt.value ||
    expiresAt.value <= requestedAt.value ||
    terminal !== (terminalAt !== undefined) ||
    (terminalAt && terminalAt.value < requestedAt.value)
  ) {
    throw projectionMismatch();
  }
  const artifact =
    record["artifact"] === undefined
      ? undefined
      : projectArtifact(record["artifact"], expiresAt.value);
  if ((state === "succeeded") !== (artifact !== undefined)) {
    throw projectionMismatch();
  }
  return {
    id,
    stream,
    ...(scope.kind === "tenant" ? { tenantId: scope.tenantId } : {}),
    requesterUserId,
    filter,
    filterSha256: String(record["filterSha256"]),
    projectionVersion: 1,
    format: "jsonl",
    state,
    revision,
    attempts,
    maximumAttempts,
    failureCode,
    requestedAt: requestedAt.text,
    updatedAt: updatedAt.text,
    availableAt: availableAt.text,
    expiresAt: expiresAt.text,
    ...(terminalAt ? { terminalAt: terminalAt.text } : {}),
    ...(artifact ? { artifact } : {}),
  };
}

function projectFilter(
  value: unknown,
  surface: "tenant" | "platform",
): AuditExportFilter {
  const record = exactRecord(value, filterKeys);
  if (surface === "platform" && record["actorServiceAccountId"] !== undefined) {
    throw projectionMismatch();
  }
  const filter = { ...record } as AuditExportFilter;
  if (
    (filter.actorType !== undefined &&
      !["user", "service_account", "system"].includes(filter.actorType)) ||
    (filter.outcome !== undefined &&
      !["success", "failure", "denied"].includes(filter.outcome)) ||
    ![filter.actorUserId, filter.actorServiceAccountId, filter.resourceId]
      .filter((item): item is string => item !== undefined)
      .every((item) => uuidPattern.test(item)) ||
    ![filter.occurredFrom, filter.occurredBefore]
      .filter((item): item is string => item !== undefined)
      .every((item) => parseRfc3339Instant(item) !== undefined) ||
    Object.values(filter).some(
      (item) =>
        typeof item === "string" && (item.length === 0 || item.length > 500),
    )
  ) {
    throw projectionMismatch();
  }
  return filter;
}

function projectArtifact(value: unknown, jobExpiry: bigint) {
  const record = exactRecord(
    value,
    new Set(["id", "sha256", "rows", "bytes", "expiresAt"]),
  );
  const expiresAt = instant(record["expiresAt"]);
  if (
    !sha256Pattern.test(String(record["sha256"])) ||
    expiresAt.value !== jobExpiry
  ) {
    throw projectionMismatch();
  }
  return {
    id: requireUuid(record["id"], "artifact"),
    sha256: String(record["sha256"]),
    rows: boundedInteger(record["rows"], 0, 10_000_000),
    bytes: boundedInteger(record["bytes"], 0, 1_073_741_824),
    expiresAt: expiresAt.text,
  };
}

function projectRetention(
  value: unknown,
  scope: AuditOperationsScope,
): AuditRetentionState {
  const record = exactRecord(
    value,
    new Set(["stream", "tenantId", "policy", "anchor", "activeLegalHold"]),
  );
  if (
    record["stream"] !== scope.kind ||
    (scope.kind === "tenant" && record["tenantId"] !== scope.tenantId) ||
    (scope.kind === "platform" && record["tenantId"] !== undefined)
  ) {
    throw projectionMismatch(
      "The retention state crossed its authorization boundary.",
    );
  }
  const policy = exactRecord(
    record["policy"],
    new Set(["retentionDays", "revision", "updatedAt"]),
  );
  const anchor = exactRecord(
    record["anchor"],
    new Set([
      "retainedThroughSequence",
      "retainedThroughHash",
      "revision",
      "updatedAt",
    ]),
  );
  const retainedThroughSequence = boundedInteger(
    anchor["retainedThroughSequence"],
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const retainedThroughHash = String(anchor["retainedThroughHash"]);
  if (
    !sha256Pattern.test(retainedThroughHash) ||
    (retainedThroughSequence === 0 && retainedThroughHash !== "0".repeat(64))
  ) {
    throw projectionMismatch();
  }
  const activeLegalHold =
    record["activeLegalHold"] === undefined
      ? undefined
      : projectHold(record["activeLegalHold"], "active");
  return {
    stream: scope.kind,
    ...(scope.kind === "tenant" ? { tenantId: scope.tenantId } : {}),
    policy: {
      retentionDays: boundedInteger(policy["retentionDays"], 30, 3_650),
      revision: positiveInteger(policy["revision"]),
      updatedAt: instant(policy["updatedAt"]).text,
    },
    anchor: {
      retainedThroughSequence,
      retainedThroughHash,
      revision: positiveInteger(anchor["revision"]),
      updatedAt: instant(anchor["updatedAt"]).text,
    },
    ...(activeLegalHold ? { activeLegalHold } : {}),
  };
}

function projectRetentionMutation(
  value: unknown,
  scope: AuditOperationsScope,
): AuditRetentionMutationResult {
  const record = exactRecord(value, new Set(["state", "replayed"]));
  if (typeof record["replayed"] !== "boolean") throw projectionMismatch();
  return {
    state: projectRetention(record["state"], scope),
    replayed: record["replayed"],
  };
}

function projectHoldMutation(value: unknown): AuditLegalHoldMutationResult {
  const record = exactRecord(value, new Set(["hold", "replayed"]));
  if (typeof record["replayed"] !== "boolean") throw projectionMismatch();
  return {
    hold: projectHold(record["hold"]),
    replayed: record["replayed"],
  };
}

function projectHold(
  value: unknown,
  expectedState?: "active" | "released",
): AuditLegalHold {
  const record = exactRecord(
    value,
    new Set(["id", "state", "revision", "placedAt", "releasedAt"]),
  );
  const state = record["state"];
  if (
    (state !== "active" && state !== "released") ||
    (expectedState !== undefined && state !== expectedState)
  ) {
    throw projectionMismatch();
  }
  const placedAt = instant(record["placedAt"]);
  const releasedAt =
    record["releasedAt"] === undefined
      ? undefined
      : instant(record["releasedAt"]);
  if (
    (state === "released") !== (releasedAt !== undefined) ||
    (releasedAt && releasedAt.value < placedAt.value)
  ) {
    throw projectionMismatch();
  }
  return {
    id: requireUuid(record["id"], "legal hold"),
    state,
    revision: positiveInteger(record["revision"]),
    placedAt: placedAt.text,
    ...(releasedAt ? { releasedAt: releasedAt.text } : {}),
  };
}

function mutationHeaders(input: {
  csrfToken: string;
  idempotencyKey: string;
  reason: string;
}) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "X-Audit-Reason": input.reason,
    "X-CSRF-Token": input.csrfToken,
  };
}

function requireMutation(input: {
  csrfToken: string;
  idempotencyKey: string;
  reason: string;
}): void {
  if (
    input.csrfToken.length < 1 ||
    input.csrfToken.length > 4_096 ||
    !idempotencyPattern.test(input.idempotencyKey) ||
    !visibleReasonPattern.test(input.reason) ||
    input.reason !== input.reason.trim() ||
    input.reason.includes(",") ||
    reasonSensitivePattern.test(input.reason)
  ) {
    throw invalid("Provide a concise, redacted operational reason.");
  }
}

function requireTenant(value: string): string {
  if (!isAuditTenantId(value))
    throw invalid("A valid tenant context is required.");
  return value;
}

function requireExportId(value: string): void {
  requireUuid(value, "export");
}

function requireUuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !uuidV7Pattern.test(value)) {
    throw invalid(`The ${label} identifier is invalid.`);
  }
  return value;
}

function requireRevision(value: unknown): number {
  return positiveInteger(value);
}

function positiveInteger(value: unknown): number {
  return boundedInteger(value, 1, 2_147_483_647);
}

function boundedInteger(
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

function instant(value: unknown): { text: string; value: bigint } {
  if (typeof value !== "string") throw projectionMismatch();
  const parsed = parseRfc3339Instant(value);
  if (parsed === undefined) throw projectionMismatch();
  return { text: value, value: parsed };
}

function exactRecord(
  value: unknown,
  allowed: ReadonlySet<string>,
): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !Object.keys(value).every((key) => allowed.has(key))
  ) {
    throw projectionMismatch();
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function auditStream(value: unknown): AuditExportJob["stream"] {
  if (value !== "tenant" && value !== "platform") throw projectionMismatch();
  return value;
}

function auditExportState(value: unknown): AuditExportJob["state"] {
  if (typeof value !== "string" || !exportStates.has(value)) {
    throw projectionMismatch();
  }
  switch (value) {
    case "pending":
    case "running":
    case "cancellation_requested":
    case "succeeded":
    case "failed":
    case "cancelled":
    case "authorization_revoked":
    case "expired":
      return value;
    default:
      throw projectionMismatch();
  }
}

function auditFailureCode(value: unknown): AuditExportJob["failureCode"] {
  if (typeof value !== "string" || !failureCodes.has(value)) {
    throw projectionMismatch();
  }
  switch (value) {
    case "none":
    case "transient_storage":
    case "transient_database":
    case "authorization_revoked":
    case "output_limit":
    case "lease_expired":
    case "expired":
    case "internal":
      return value;
    default:
      throw projectionMismatch();
  }
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw responseError(result.response);
}

function requireProtectedResponse(response: Response | undefined): void {
  const directives = response?.headers
    .get("Cache-Control")
    ?.toLowerCase()
    .split(",")
    .map((value) => value.trim());
  if (!directives?.includes("no-store")) {
    throw projectionMismatch("The audit operation response was cacheable.");
  }
}

function requireVersionEtag(
  response: Response | undefined,
  revision: number,
): void {
  if (response?.headers.get("ETag") !== versionEtag(revision)) {
    throw projectionMismatch(
      "The audit operation revision was not strongly bound.",
    );
  }
}

function versionEtag(revision: number): string {
  return `"v${requireRevision(revision)}"`;
}

function invalid(message: string): AuditApiError {
  return new AuditApiError(message, 400, "invalid_request");
}

function projectionMismatch(
  message = "The audit operation projection was not safe to display.",
): AuditApiError {
  return new AuditApiError(message, undefined, "projection_mismatch");
}

function responseError(response?: Response): AuditApiError {
  const status = response?.status;
  const message =
    status === 401
      ? "The current session was not accepted."
      : status === 403
        ? "The server denied this audit operation."
        : status === 409 || status === 412
          ? "The audit operation changed. Refresh before retrying."
          : status === 503
            ? "Audit operations are temporarily unavailable."
            : "The audit operation could not be completed.";
  return new AuditApiError(message, status);
}
