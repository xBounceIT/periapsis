import {
  cancelTenantTicketExport,
  getTenantTicketExport,
  prepareTenantTicketExportDownload,
  requestTenantTicketExport,
  type TicketExportCommentScope,
  type TicketExportFailureCode,
  type TicketExportJobRequest,
  type TicketExportState,
} from "@periapsis/contracts";

import { currentInstant, parseRfc3339Instant } from "./rfc3339-instant";
import { sessionAwareFetch } from "./session-transition-transport";
import { hasControlCharacters } from "./text-validation";
import { TicketingApiError, type TicketKind } from "./ticketing-api";

export interface TicketExportSavedViewPinView {
  id: string;
  ownerMembershipId: string;
  revision: number;
  specSha256: string;
}

export interface TicketExportQueryView {
  catalogSha256: string;
  querySha256: string;
  savedView?: TicketExportSavedViewPinView;
  source: "inline" | "saved_view";
}

export interface TicketExportArtifactView {
  bytes: number;
  expiresAt: string;
  id: string;
  rows: number;
  sha256: string;
}

export interface TicketExportJobView {
  artifact?: TicketExportArtifactView;
  attempts: number;
  availableAt: string;
  comments: TicketExportCommentScope;
  expiresAt: string;
  failureCode: TicketExportFailureCode;
  id: string;
  kind: TicketKind;
  maximumAttempts: number;
  maximumBytes: number;
  maximumRows: number;
  ownerMembershipId: string;
  query: TicketExportQueryView;
  requestedAt: string;
  requesterUserId: string;
  revision: number;
  state: TicketExportState;
  tenantId: string;
  terminalAt?: string;
  updatedAt: string;
}

export interface TicketExportMutationView {
  job: TicketExportJobView;
  replayed: boolean;
}

export interface TicketExportPreparedDownloadView {
  artifact: TicketExportArtifactView;
  downloadUrl: string;
  expiresAt: string;
}

export interface TicketExportApi {
  request(input: {
    body: TicketExportJobRequest;
    csrfToken: string;
    idempotencyKey: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketExportMutationView>;
  get(input: {
    jobId: string;
    kind: TicketKind;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketExportJobView>;
  download(input: {
    csrfToken: string;
    expectedArtifact: TicketExportArtifactView;
    jobId: string;
    kind: TicketKind;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketExportPreparedDownloadView>;
  cancel(input: {
    csrfToken: string;
    expectedRevision: number;
    idempotencyKey: string;
    jobId: string;
    kind: TicketKind;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketExportMutationView>;
}

interface GeneratedResult<T> {
  data?: T;
  error?: unknown;
  response?: Response;
}

interface ProjectedInstant {
  text: string;
  value: bigint;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const requestIdPattern = /^[A-Za-z0-9._~-]{1,128}$/u;
const workflowKeyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const maximumRows = 100_000;
const maximumBytes = 512 * 1024 * 1024;
const defaultRows = 10_000;
const defaultBytes = 64 * 1024 * 1024;
const defaultRetentionSeconds = 86_400;
const minimumRetentionNanoseconds = 900n * 1_000_000_000n;
const maximumRetentionNanoseconds = 604_800n * 1_000_000_000n;
const maximumDownloadLifetimeNanoseconds = 300n * 1_000_000_000n;
const retryableFailureCodes = new Set<TicketExportFailureCode>([
  "transient_storage",
  "transient_database",
  "internal",
]);
const severities = new Set([
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);
const priorities = new Set(["low", "medium", "high", "urgent", "critical"]);
const coreColumns = new Set([
  "ticket",
  "state",
  "risk",
  "assignment",
  "category",
  "source",
  "customer_visibility",
  "created",
  "updated",
]);
const coreSorts = new Set([
  "updated_at",
  "created_at",
  "priority",
  "oldest_unclaimed",
]);
const safeProblemCodes = new Set([
  "invalid_request",
  "authentication_failed",
  "forbidden",
  "not_found",
  "conflict",
  "precondition_failed",
  "precondition_required",
  "rate_limited",
  "service_unavailable",
  "internal_error",
]);

export const ticketExportApi: TicketExportApi = {
  async request({ body, csrfToken, idempotencyKey, signal, tenantId }) {
    requireMutationContext(csrfToken, idempotencyKey, tenantId);
    validateExportRequest(body);
    const result = await requestTenantTicketExport({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    const projected = projectMutation(unwrap(result), tenantId, body.kind);
    validateRequestReceipt(projected.job, body);
    requirePrivateResponse(result.response, 202);
    const expectedLocation = `/api/v1/tenants/${tenantId}/ticket-exports/${projected.job.id}`;
    if (result.response?.headers.get("Location") !== expectedLocation) {
      throw projectionMismatch(
        "The export creation location was not canonical.",
      );
    }
    return projected;
  },

  async get({ jobId, kind, signal, tenantId }) {
    requireReadCoordinates(jobId, kind, tenantId);
    const result = await getTenantTicketExport({
      ...sameOrigin,
      path: { jobId, tenantId },
      query: { kind },
      ...(signal ? { signal } : {}),
    });
    const projected = projectJob(unwrap(result), tenantId, kind, jobId);
    requirePrivateResponse(result.response, 200);
    return projected;
  },

  async download({
    csrfToken,
    expectedArtifact,
    jobId,
    kind,
    signal,
    tenantId,
  }) {
    requireReadCoordinates(jobId, kind, tenantId);
    requireDownloadContext(csrfToken, expectedArtifact);
    const requestedAt = currentInstant();
    const result = await prepareTenantTicketExportDownload({
      ...sameOrigin,
      headers: { "X-CSRF-Token": csrfToken },
      path: { jobId, tenantId },
      query: { kind },
      ...(signal ? { signal } : {}),
    });
    const projected = projectPreparedDownload(
      unwrap(result),
      expectedArtifact,
      requestedAt,
    );
    requirePrivateResponse(result.response, 200);
    return projected;
  },

  async cancel({
    csrfToken,
    expectedRevision,
    idempotencyKey,
    jobId,
    kind,
    signal,
    tenantId,
  }) {
    requireMutationContext(csrfToken, idempotencyKey, tenantId);
    requireReadCoordinates(jobId, kind, tenantId);
    const revision = resourceVersion(expectedRevision, 2_147_483_646);
    const result = await cancelTenantTicketExport({
      ...sameOrigin,
      body: { expectedRevision: revision, kind },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { jobId, tenantId },
      ...(signal ? { signal } : {}),
    });
    const projected = projectMutation(unwrap(result), tenantId, kind, jobId);
    validateCancellationReceipt(projected.job, revision);
    requirePrivateResponse(result.response, 200);
    return projected;
  },
};

function validateRequestReceipt(
  job: TicketExportJobView,
  request: TicketExportJobRequest,
): void {
  const expectedRows = request.maximumRows ?? defaultRows;
  const expectedBytes = request.maximumBytes ?? defaultBytes;
  const expectedRetention =
    BigInt(request.retentionSeconds ?? defaultRetentionSeconds) *
    1_000_000_000n;
  const requestedAt = parseRfc3339Instant(job.requestedAt);
  const expiresAt = parseRfc3339Instant(job.expiresAt);
  if (
    job.comments !== request.comments ||
    job.maximumRows !== expectedRows ||
    job.maximumBytes !== expectedBytes ||
    job.maximumAttempts !== 5 ||
    job.state !== "pending" ||
    job.revision !== 1 ||
    job.attempts !== 0 ||
    requestedAt === undefined ||
    expiresAt === undefined ||
    expiresAt - requestedAt !== expectedRetention
  ) {
    throw projectionMismatch("The export receipt did not match the request.");
  }
  const source = asRecord(request.source);
  if (source["source"] === "inline") {
    if (job.query.source !== "inline" || job.query.savedView !== undefined) {
      throw projectionMismatch(
        "The export receipt did not bind the inline snapshot.",
      );
    }
    return;
  }
  const requestedPin = asRecord(source["savedView"]);
  const receiptPin = job.query.savedView;
  if (
    job.query.source !== "saved_view" ||
    receiptPin === undefined ||
    receiptPin.id !== requestedPin["id"] ||
    receiptPin.revision !== requestedPin["expectedRevision"] ||
    receiptPin.specSha256 !== requestedPin["expectedSpecSha256"] ||
    job.query.querySha256 !== requestedPin["expectedSpecSha256"]
  ) {
    throw projectionMismatch("The export receipt did not bind the saved view.");
  }
}

function validateCancellationReceipt(
  job: TicketExportJobView,
  expectedRevision: number,
): void {
  if (
    job.revision !== expectedRevision + 1 ||
    (job.state !== "cancelled" && job.state !== "cancellation_requested")
  ) {
    throw projectionMismatch(
      "The export cancellation receipt was not canonical.",
    );
  }
}

function validateExportRequest(value: TicketExportJobRequest): void {
  const body = exactRecord(
    value,
    [
      "comments",
      "kind",
      "maximumBytes",
      "maximumRows",
      "retentionSeconds",
      "source",
    ],
    ["comments", "kind", "source"],
  );
  ticketKind(body["kind"]);
  commentScope(body["comments"]);
  optionalBoundedInteger(body["maximumRows"], 1, maximumRows);
  optionalBoundedInteger(body["maximumBytes"], 1, maximumBytes);
  optionalBoundedInteger(body["retentionSeconds"], 900, 604_800);

  const source = asRecord(body["source"]);
  if (source["source"] === "inline") {
    exactKeys(source, ["source", "spec"], ["source", "spec"]);
    validateInlineSpec(source["spec"]);
    return;
  }
  if (source["source"] !== "saved_view") throw projectionMismatch();
  exactKeys(source, ["savedView", "source"], ["savedView", "source"]);
  const savedView = exactRecord(
    source["savedView"],
    ["expectedRevision", "expectedSpecSha256", "id"],
    ["expectedRevision", "expectedSpecSha256", "id"],
  );
  canonicalUUIDv7(savedView["id"]);
  resourceVersion(savedView["expectedRevision"]);
  canonicalDigest(savedView["expectedSpecSha256"]);
}

function validateInlineSpec(value: unknown): void {
  const spec = exactRecord(
    value,
    ["columns", "filters", "sort"],
    ["columns", "filters", "sort"],
  );
  const filters = exactRecord(
    spec["filters"],
    [
      "assignedTeamId",
      "assigneeUserId",
      "claimedBy",
      "customerVisible",
      "custom",
      "priorities",
      "queue",
      "search",
      "severities",
      "states",
    ],
    ["custom", "priorities", "queue", "severities", "states"],
  );
  if (
    !boundedUniqueStrings(filters["states"], 20, workflowKeyPattern) ||
    !boundedEnumList(filters["severities"], severities, 5) ||
    !boundedEnumList(filters["priorities"], priorities, 5) ||
    !["all", "assigned_to_me", "my_operator_teams", "unassigned"].includes(
      String(filters["queue"]),
    ) ||
    !optionalUUIDv7(filters["assignedTeamId"]) ||
    !optionalUUIDv7(filters["assigneeUserId"]) ||
    !optionalUUIDv7(filters["claimedBy"]) ||
    (filters["customerVisible"] !== undefined &&
      typeof filters["customerVisible"] !== "boolean") ||
    (filters["search"] !== undefined && !boundedText(filters["search"], 240)) ||
    !Array.isArray(filters["custom"]) ||
    filters["custom"].length > 8
  ) {
    throw projectionMismatch("The inline export filters were not canonical.");
  }

  const pins = new Map<string, number>();
  const filterIdentities = new Set<string>();
  for (const candidate of filters["custom"]) {
    const filter = exactRecord(
      candidate,
      ["definitionId", "expectedDefinitionVersion", "operator", "value"],
      ["definitionId", "expectedDefinitionVersion", "operator", "value"],
    );
    const id = canonicalUUIDv7(filter["definitionId"]);
    const revision = resourceVersion(filter["expectedDefinitionVersion"]);
    if (
      filter["operator"] !== "equal" ||
      !scalarInput(filter["value"]) ||
      filterIdentities.has(id)
    ) {
      throw projectionMismatch(
        "The inline export custom filters were not canonical.",
      );
    }
    filterIdentities.add(id);
    registerPin(pins, `custom_field:${id}`, revision);
  }

  if (
    !Array.isArray(spec["columns"]) ||
    spec["columns"].length < 1 ||
    spec["columns"].length > 64
  ) {
    throw projectionMismatch("The inline export columns were not canonical.");
  }
  const columnIdentities = new Set<string>();
  let visibleTicketColumn = false;
  for (const candidate of spec["columns"]) {
    const column = exactRecord(
      candidate,
      [
        "coreKey",
        "definitionId",
        "expectedDefinitionVersion",
        "pin",
        "source",
        "visible",
        "width",
      ],
      ["pin", "source", "visible"],
    );
    if (
      typeof column["visible"] !== "boolean" ||
      !["none", "start", "end"].includes(String(column["pin"]))
    ) {
      throw projectionMismatch();
    }
    optionalBoundedInteger(column["width"], 80, 1_200);
    let identity: string;
    if (column["source"] === "core") {
      if (
        typeof column["coreKey"] !== "string" ||
        !coreColumns.has(column["coreKey"]) ||
        column["definitionId"] !== undefined ||
        column["expectedDefinitionVersion"] !== undefined
      ) {
        throw projectionMismatch();
      }
      identity = `core:${column["coreKey"]}`;
      visibleTicketColumn ||=
        column["coreKey"] === "ticket" && column["visible"];
    } else if (
      column["source"] === "custom_field" ||
      column["source"] === "sla"
    ) {
      if (column["coreKey"] !== undefined) throw projectionMismatch();
      const id = canonicalUUIDv7(column["definitionId"]);
      const revision = resourceVersion(column["expectedDefinitionVersion"]);
      identity = `${column["source"]}:${id}`;
      registerPin(pins, identity, revision);
    } else {
      throw projectionMismatch();
    }
    if (columnIdentities.has(identity)) throw projectionMismatch();
    columnIdentities.add(identity);
  }
  if (!visibleTicketColumn) throw projectionMismatch();
  validateInlineSort(spec["sort"], pins, columnIdentities);
}

function validateInlineSort(
  value: unknown,
  pins: ReadonlyMap<string, number>,
  columns: ReadonlySet<string>,
): void {
  const sort = exactRecord(
    value,
    [
      "coreKey",
      "definitionId",
      "direction",
      "expectedDefinitionVersion",
      "nulls",
      "source",
    ],
    ["direction", "nulls", "source"],
  );
  if (
    !["asc", "desc"].includes(String(sort["direction"])) ||
    !["first", "last"].includes(String(sort["nulls"]))
  ) {
    throw projectionMismatch();
  }
  if (sort["source"] === "core") {
    if (
      typeof sort["coreKey"] !== "string" ||
      !coreSorts.has(sort["coreKey"]) ||
      sort["definitionId"] !== undefined ||
      sort["expectedDefinitionVersion"] !== undefined ||
      sort["nulls"] !== "last" ||
      (sort["coreKey"] === "oldest_unclaimed" && sort["direction"] !== "asc")
    ) {
      throw projectionMismatch();
    }
    return;
  }
  if (sort["source"] !== "custom_field" && sort["source"] !== "sla") {
    throw projectionMismatch();
  }
  if (sort["coreKey"] !== undefined) throw projectionMismatch();
  const id = canonicalUUIDv7(sort["definitionId"]);
  const revision = resourceVersion(sort["expectedDefinitionVersion"]);
  const identity = `${sort["source"]}:${id}`;
  if (pins.get(identity) !== revision || !columns.has(identity)) {
    throw projectionMismatch();
  }
}

function projectMutation(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
  jobId?: string,
): TicketExportMutationView {
  const record = exactRecord(value, ["job", "replayed"], ["job", "replayed"]);
  if (typeof record["replayed"] !== "boolean") throw projectionMismatch();
  return {
    job: projectJob(record["job"], tenantId, kind, jobId),
    replayed: record["replayed"],
  };
}

function projectJob(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
  expectedJobId?: string,
): TicketExportJobView {
  const record = exactRecord(
    value,
    [
      "artifact",
      "attempts",
      "audience",
      "availableAt",
      "comments",
      "expiresAt",
      "failureCode",
      "format",
      "id",
      "kind",
      "maximumAttempts",
      "maximumBytes",
      "maximumRows",
      "ownerMembershipId",
      "projectionVersion",
      "query",
      "requestedAt",
      "requesterUserId",
      "revision",
      "state",
      "tenantId",
      "terminalAt",
      "updatedAt",
    ],
    [
      "attempts",
      "audience",
      "availableAt",
      "comments",
      "expiresAt",
      "failureCode",
      "format",
      "id",
      "kind",
      "maximumAttempts",
      "maximumBytes",
      "maximumRows",
      "ownerMembershipId",
      "projectionVersion",
      "query",
      "requestedAt",
      "requesterUserId",
      "revision",
      "state",
      "tenantId",
      "updatedAt",
    ],
  );
  const comments = commentScope(record["comments"]);
  const state = exportState(record["state"]);
  const failureCode = exportFailureCode(record["failureCode"]);
  if (
    record["tenantId"] !== tenantId ||
    record["kind"] !== kind ||
    record["audience"] !== "operator" ||
    record["projectionVersion"] !== 1 ||
    record["format"] !== "csv" ||
    (expectedJobId !== undefined && record["id"] !== expectedJobId)
  ) {
    throw projectionMismatch();
  }
  const id = canonicalUUIDv7(record["id"]);
  const requesterUserId = canonicalUUIDv7(record["requesterUserId"]);
  const ownerMembershipId = canonicalUUIDv7(record["ownerMembershipId"]);
  const maximumRowCount = boundedInteger(record["maximumRows"], 1, maximumRows);
  const maximumByteCount = boundedInteger(
    record["maximumBytes"],
    1,
    maximumBytes,
  );
  const maximumAttemptCount = boundedInteger(record["maximumAttempts"], 1, 5);
  const attempts = boundedInteger(record["attempts"], 0, maximumAttemptCount);
  const revision = resourceVersion(record["revision"]);
  if (revision < attempts + 1) throw projectionMismatch();

  const requestedAt = projectedInstant(record["requestedAt"]);
  const updatedAt = projectedInstant(record["updatedAt"]);
  const availableAt = projectedInstant(record["availableAt"]);
  const expiresAt = projectedInstant(record["expiresAt"]);
  const retention = expiresAt.value - requestedAt.value;
  if (
    updatedAt.value < requestedAt.value ||
    availableAt.value < requestedAt.value ||
    availableAt.value > expiresAt.value ||
    retention < minimumRetentionNanoseconds ||
    retention > maximumRetentionNanoseconds
  ) {
    throw projectionMismatch("The export timestamps were not canonical.");
  }

  const terminalAt =
    record["terminalAt"] === undefined
      ? undefined
      : projectedInstant(record["terminalAt"]);
  validateJobState(
    state,
    failureCode,
    attempts,
    maximumAttemptCount,
    revision,
    requestedAt,
    updatedAt,
    availableAt,
    expiresAt,
    terminalAt,
    record["artifact"] !== undefined,
  );

  const artifact =
    record["artifact"] === undefined
      ? undefined
      : projectArtifact(
          record["artifact"],
          maximumRowCount,
          maximumByteCount,
          expiresAt,
          terminalAt,
        );
  const query = projectQuery(record["query"], ownerMembershipId);
  return {
    attempts,
    availableAt: availableAt.text,
    comments,
    expiresAt: expiresAt.text,
    failureCode,
    id,
    kind,
    maximumAttempts: maximumAttemptCount,
    maximumBytes: maximumByteCount,
    maximumRows: maximumRowCount,
    ownerMembershipId,
    query,
    requestedAt: requestedAt.text,
    requesterUserId,
    revision,
    state,
    tenantId,
    updatedAt: updatedAt.text,
    ...(terminalAt === undefined ? {} : { terminalAt: terminalAt.text }),
    ...(artifact === undefined ? {} : { artifact }),
  };
}

function validateJobState(
  state: TicketExportState,
  failureCode: TicketExportFailureCode,
  attempts: number,
  maximumAttempts: number,
  revision: number,
  requestedAt: ProjectedInstant,
  updatedAt: ProjectedInstant,
  availableAt: ProjectedInstant,
  expiresAt: ProjectedInstant,
  terminalAt: ProjectedInstant | undefined,
  hasArtifact: boolean,
): void {
  const terminal =
    state === "succeeded" || state === "failed" || state === "cancelled";
  if (
    terminal !== (terminalAt !== undefined) ||
    (terminalAt !== undefined &&
      (terminalAt.value < requestedAt.value ||
        terminalAt.value > updatedAt.value ||
        terminalAt.value > expiresAt.value)) ||
    (state === "succeeded") !== hasArtifact
  ) {
    throw projectionMismatch();
  }
  switch (state) {
    case "pending":
      if (!(
        (attempts === 0 &&
          revision === 1 &&
          failureCode === "none" &&
          updatedAt.value === requestedAt.value &&
          availableAt.value === requestedAt.value) ||
        (attempts > 0 &&
          availableAt.value >= updatedAt.value &&
          (retryableFailureCodes.has(failureCode) ||
            failureCode === "lease_expired"))
      )) {
        throw projectionMismatch();
      }
      return;
    case "running":
    case "cancellation_requested":
      if (
        attempts < 1 ||
        failureCode !== "none" ||
        availableAt.value > updatedAt.value
      ) {
        throw projectionMismatch();
      }
      return;
    case "succeeded":
      if (
        attempts < 1 ||
        failureCode !== "none" ||
        terminalAt?.value !== updatedAt.value ||
        expiresAt.value <= updatedAt.value
      ) {
        throw projectionMismatch();
      }
      return;
    case "failed":
      if (
        failureCode === "none" ||
        terminalAt?.value !== updatedAt.value ||
        (attempts === 0 &&
          failureCode !== "expired" &&
          failureCode !== "authorization_revoked") ||
        (failureCode === "expired" && terminalAt.value !== expiresAt.value) ||
        (failureCode === "authorization_revoked" &&
          terminalAt.value >= expiresAt.value) ||
        (failureCode === "lease_expired" && attempts !== maximumAttempts)
      ) {
        throw projectionMismatch();
      }
      return;
    case "cancelled":
      if (failureCode !== "none" || terminalAt?.value !== updatedAt.value) {
        throw projectionMismatch();
      }
  }
}

function projectQuery(
  value: unknown,
  ownerMembershipId: string,
): TicketExportQueryView {
  const record = exactRecord(
    value,
    ["catalogSha256", "effectiveSpec", "querySha256", "savedView", "source"],
    ["catalogSha256", "effectiveSpec", "querySha256", "source"],
  );
  validateBoundedEffectiveSpec(record["effectiveSpec"]);
  const querySha256 = canonicalDigest(record["querySha256"]);
  const catalogSha256 = canonicalDigest(record["catalogSha256"]);
  if (record["source"] === "inline") {
    if (record["savedView"] !== undefined) throw projectionMismatch();
    return { catalogSha256, querySha256, source: "inline" };
  }
  if (record["source"] !== "saved_view") throw projectionMismatch();
  const saved = exactRecord(
    record["savedView"],
    ["id", "ownerMembershipId", "revision", "specSha256"],
    ["id", "ownerMembershipId", "revision", "specSha256"],
  );
  if (saved["ownerMembershipId"] !== ownerMembershipId)
    throw projectionMismatch();
  const savedView = {
    id: canonicalUUIDv7(saved["id"]),
    ownerMembershipId,
    revision: resourceVersion(saved["revision"]),
    specSha256: canonicalDigest(saved["specSha256"]),
  };
  if (savedView.specSha256 !== querySha256) throw projectionMismatch();
  return { catalogSha256, querySha256, savedView, source: "saved_view" };
}

function validateBoundedEffectiveSpec(value: unknown): void {
  const spec = exactRecord(
    value,
    ["columns", "filters", "sort"],
    ["columns", "filters", "sort"],
  );
  if (
    !Array.isArray(spec["columns"]) ||
    spec["columns"].length < 1 ||
    spec["columns"].length > 64 ||
    !isRecord(spec["filters"]) ||
    !isRecord(spec["sort"])
  ) {
    throw projectionMismatch();
  }
  let nodes = 0;
  const visit = (candidate: unknown, depth: number): void => {
    nodes += 1;
    if (nodes > 2_048 || depth > 10) throw projectionMismatch();
    if (
      candidate === null ||
      typeof candidate === "boolean" ||
      (typeof candidate === "number" &&
        Number.isFinite(candidate) &&
        (!Number.isInteger(candidate) || Number.isSafeInteger(candidate)))
    ) {
      return;
    }
    if (typeof candidate === "string") {
      if (new TextEncoder().encode(candidate).byteLength > 131_072) {
        throw projectionMismatch();
      }
      return;
    }
    if (Array.isArray(candidate)) {
      if (candidate.length > 100) throw projectionMismatch();
      for (const item of candidate) visit(item, depth + 1);
      return;
    }
    if (!isRecord(candidate)) throw projectionMismatch();
    const entries = Object.entries(candidate);
    if (
      entries.length > 64 ||
      entries.some(([key]) => new TextEncoder().encode(key).byteLength > 128)
    ) {
      throw projectionMismatch();
    }
    for (const [, item] of entries) visit(item, depth + 1);
  };
  visit(spec, 0);
}

function projectArtifact(
  value: unknown,
  rowLimit: number,
  byteLimit: number,
  jobExpiresAt: ProjectedInstant,
  terminalAt: ProjectedInstant | undefined,
): TicketExportArtifactView {
  const record = exactRecord(
    value,
    ["bytes", "expiresAt", "id", "rows", "sha256"],
    ["bytes", "expiresAt", "id", "rows", "sha256"],
  );
  const expiresAt = projectedInstant(record["expiresAt"]);
  if (
    expiresAt.value !== jobExpiresAt.value ||
    terminalAt === undefined ||
    expiresAt.value <= terminalAt.value
  ) {
    throw projectionMismatch();
  }
  return {
    bytes: boundedInteger(record["bytes"], 1, byteLimit),
    expiresAt: expiresAt.text,
    id: canonicalUUIDv7(record["id"]),
    rows: boundedInteger(record["rows"], 0, rowLimit),
    sha256: canonicalDigest(record["sha256"]),
  };
}

function projectPreparedDownload(
  value: unknown,
  expectedArtifact: TicketExportArtifactView,
  requestedAt: bigint,
): TicketExportPreparedDownloadView {
  const record = exactRecord(
    value,
    ["artifact", "downloadUrl", "expiresAt"],
    ["artifact", "downloadUrl", "expiresAt"],
  );
  const candidate = exactRecord(
    record["artifact"],
    ["bytes", "expiresAt", "id", "rows", "sha256"],
    ["bytes", "expiresAt", "id", "rows", "sha256"],
  );
  const artifact = {
    bytes: boundedInteger(candidate["bytes"], 1, maximumBytes),
    expiresAt: projectedInstant(candidate["expiresAt"]).text,
    id: canonicalUUIDv7(candidate["id"]),
    rows: boundedInteger(candidate["rows"], 0, maximumRows),
    sha256: canonicalDigest(candidate["sha256"]),
  };
  const artifactExpiry = parseRfc3339Instant(artifact.expiresAt);
  const expectedArtifactExpiry = parseRfc3339Instant(
    expectedArtifact.expiresAt,
  );
  const expiresAt = projectedInstant(record["expiresAt"]);
  if (
    artifact.id !== expectedArtifact.id ||
    artifact.sha256 !== expectedArtifact.sha256 ||
    artifact.rows !== expectedArtifact.rows ||
    artifact.bytes !== expectedArtifact.bytes ||
    artifactExpiry === undefined ||
    expectedArtifactExpiry === undefined ||
    artifactExpiry !== expectedArtifactExpiry ||
    expiresAt.value > artifactExpiry ||
    expiresAt.value <= currentInstant() ||
    expiresAt.value > requestedAt + maximumDownloadLifetimeNanoseconds
  ) {
    throw projectionMismatch(
      "The download capability did not match the authorized artifact.",
    );
  }
  return {
    artifact,
    downloadUrl: safeDownloadURL(record["downloadUrl"]),
    expiresAt: expiresAt.text,
  };
}

function requireReadCoordinates(
  jobId: string,
  kind: TicketKind,
  tenantId: string,
): void {
  canonicalUUIDv7(tenantId);
  canonicalUUIDv7(jobId);
  ticketKind(kind);
}

function requireMutationContext(
  csrfToken: string,
  idempotencyKey: string,
  tenantId: string,
): void {
  canonicalUUIDv7(tenantId);
  if (
    !boundedText(csrfToken, 512) ||
    !idempotencyKeyPattern.test(idempotencyKey)
  ) {
    throw projectionMismatch("The export mutation context was not canonical.");
  }
}

function requireDownloadContext(
  csrfToken: string,
  artifact: TicketExportArtifactView,
): void {
  if (!boundedText(csrfToken, 512)) {
    throw projectionMismatch(
      "The download authorization context was not canonical.",
    );
  }
  canonicalUUIDv7(artifact.id);
  canonicalDigest(artifact.sha256);
  boundedInteger(artifact.rows, 0, maximumRows);
  boundedInteger(artifact.bytes, 1, maximumBytes);
  projectedInstant(artifact.expiresAt);
}

function safeDownloadURL(value: unknown): string {
  if (!boundedText(value, 8_192)) throw projectionMismatch();
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw projectionMismatch("The download capability URL was not canonical.");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.host === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== ""
  ) {
    throw projectionMismatch("The download capability URL was not canonical.");
  }
  return value;
}

function requirePrivateResponse(
  response: Response | undefined,
  status: number,
): void {
  const cacheControl = response?.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (response?.status !== status || !cacheControl?.includes("no-store")) {
    throw projectionMismatch(
      "The export response was not private and canonical.",
    );
  }
}

function ticketKind(value: unknown): TicketKind {
  if (value !== "alert" && value !== "case") throw projectionMismatch();
  return value;
}

function commentScope(value: unknown): TicketExportCommentScope {
  switch (value) {
    case "none":
    case "public":
    case "public_and_private":
      return value;
    default:
      throw projectionMismatch("The export comment scope was not canonical.");
  }
}

function exportState(value: unknown): TicketExportState {
  switch (value) {
    case "pending":
    case "running":
    case "cancellation_requested":
    case "succeeded":
    case "failed":
    case "cancelled":
      return value;
    default:
      throw projectionMismatch();
  }
}

function exportFailureCode(value: unknown): TicketExportFailureCode {
  switch (value) {
    case "none":
    case "transient_storage":
    case "transient_database":
    case "authorization_revoked":
    case "snapshot_stale":
    case "output_limit":
    case "lease_expired":
    case "expired":
    case "internal":
      return value;
    default:
      throw projectionMismatch();
  }
}

function projectedInstant(value: unknown): ProjectedInstant {
  if (typeof value !== "string") throw projectionMismatch();
  const parsed = parseRfc3339Instant(value);
  if (parsed === undefined) throw projectionMismatch();
  return { text: value, value: parsed };
}

function resourceVersion(value: unknown, maximum = 2_147_483_647): number {
  return boundedInteger(value, 1, maximum);
}

function optionalBoundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): void {
  if (value !== undefined) boundedInteger(value, minimum, maximum);
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

function canonicalUUIDv7(value: unknown): string {
  if (typeof value !== "string" || !uuidV7Pattern.test(value)) {
    throw projectionMismatch("A canonical UUIDv7 identifier is required.");
  }
  return value;
}

function optionalUUIDv7(value: unknown): boolean {
  return (
    value === undefined ||
    (typeof value === "string" && uuidV7Pattern.test(value))
  );
}

function canonicalDigest(value: unknown): string {
  if (
    typeof value !== "string" ||
    !sha256Pattern.test(value) ||
    /^0+$/u.test(value)
  ) {
    throw projectionMismatch("A canonical SHA-256 receipt is required.");
  }
  return value;
}

function boundedUniqueStrings(
  value: unknown,
  maximum: number,
  pattern: RegExp,
): boolean {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    new Set(value).size === value.length &&
    value.every(
      (item, index) =>
        Object.hasOwn(value, index) &&
        typeof item === "string" &&
        pattern.test(item),
    )
  );
}

function boundedEnumList(
  value: unknown,
  allowed: ReadonlySet<string>,
  maximum: number,
): boolean {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    new Set(value).size === value.length &&
    value.every(
      (item, index) =>
        Object.hasOwn(value, index) &&
        typeof item === "string" &&
        allowed.has(item),
    )
  );
}

function boundedText(
  value: unknown,
  maximumByteLength: number,
): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    new TextEncoder().encode(value).byteLength <= maximumByteLength &&
    !hasControlCharacters(value)
  );
}

function scalarInput(value: unknown): boolean {
  return (
    typeof value === "boolean" ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))) ||
    (typeof value === "string" && Array.from(value).length <= 10_000)
  );
}

function registerPin(
  pins: Map<string, number>,
  identity: string,
  revision: number,
): void {
  const current = pins.get(identity);
  if (current !== undefined && current !== revision) throw projectionMismatch();
  pins.set(identity, revision);
}

function exactRecord(
  value: unknown,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> {
  const record = asRecord(value);
  exactKeys(record, allowed, required);
  return record;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
): void {
  const allowedSet = new Set(allowed);
  if (
    Object.keys(value).some((key) => !allowedSet.has(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  ) {
    throw projectionMismatch();
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw projectionMismatch();
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  const problem = isRecord(result.error) ? result.error : undefined;
  const rawCode = problem?.["code"];
  const rawRequestId = problem?.["requestId"];
  const code =
    typeof rawCode === "string" && safeProblemCodes.has(rawCode)
      ? rawCode
      : undefined;
  const requestId =
    typeof rawRequestId === "string" && requestIdPattern.test(rawRequestId)
      ? rawRequestId
      : undefined;
  throw new TicketingApiError(
    fallbackForStatus(result.response?.status),
    result.response?.status,
    code,
    requestId,
  );
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The export request was not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The server denied this export operation.";
    case 404:
      return "The requested export is not available.";
    case 409:
      return "This export attempt conflicts with current server state.";
    case 412:
      return "This export changed on the server. Refresh it before retrying.";
    case 429:
      return "Export requests are temporarily rate limited.";
    case 503:
      return "The asynchronous export service is unavailable.";
    default:
      return "The export operation could not be completed.";
  }
}

function projectionMismatch(
  message = "The export projection was not safe to display.",
): TicketingApiError {
  return new TicketingApiError(message, undefined, "projection_mismatch");
}
