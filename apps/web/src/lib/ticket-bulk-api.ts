import {
  cancelTenantTicketBulkJob,
  getTenantTicketBulkJob,
  listTenantTicketBulkJobResults,
  requestTenantTicketBulkJob,
  type TicketBulkJobRequest,
  type TicketBulkMutationRequest,
  type TicketBulkProgress,
  type TicketBulkState,
  type TicketBulkTargetPin,
  type TicketBulkTargetResultCode,
} from "@periapsis/contracts";

import { parseRfc3339Instant } from "./rfc3339-instant";
import { sessionAwareFetch } from "./session-transition-transport";
import {
  isSavedTicketViewSpecInput,
  TicketingApiError,
  type TicketKind,
} from "./ticketing-api";

export interface TicketBulkSelectionView {
  source: "explicit" | "query";
  targetCount: number;
  targetSetSha256: string;
  querySource?: "inline" | "saved_view";
  querySha256?: string;
  catalogSha256?: string;
  savedView?: {
    id: string;
    ownerMembershipId: string;
    revision: number;
    specSha256: string;
  };
  targets?: TicketBulkTargetPin[];
}

export interface TicketBulkJobView {
  activeBatch: boolean;
  availableAt: string;
  expiresAt: string;
  id: string;
  kind: TicketKind;
  mutation: TicketBulkMutationRequest;
  ownerMembershipId: string;
  progress: TicketBulkProgress;
  requestedAt: string;
  requesterUserId: string;
  revision: number;
  selection: TicketBulkSelectionView;
  state: TicketBulkState;
  tenantId: string;
  terminalAt?: string;
  updatedAt: string;
}

export interface TicketBulkMutationView {
  job: TicketBulkJobView;
  replayed: boolean;
}

export interface TicketBulkTargetResultView {
  recordedAt: string;
  result: TicketBulkTargetResultCode;
  sequence: number;
  targetId: string;
  targetVersion: number;
}

export interface TicketBulkResultPageView {
  items: TicketBulkTargetResultView[];
  nextCursor?: string;
}

export interface TicketBulkApi {
  request(input: {
    body: TicketBulkJobRequest;
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<TicketBulkMutationView>;
  get(input: {
    jobId: string;
    kind: TicketKind;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketBulkJobView>;
  cancel(input: {
    csrfToken: string;
    expectedRevision: number;
    idempotencyKey: string;
    jobId: string;
    kind: TicketKind;
    tenantId: string;
  }): Promise<TicketBulkMutationView>;
  listResults(input: {
    after?: string;
    jobId: string;
    kind: TicketKind;
    limit?: number;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketBulkResultPageView>;
}

interface GeneratedResult<T> {
  data?: T;
  error?: unknown;
  response?: Response;
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
const cursorPattern = /^[A-Za-z0-9_-]{1,512}$/u;
const workflowKeyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const defaultRetentionSeconds = 86_400;
const terminalStates = new Set<TicketBulkState>([
  "completed",
  "failed",
  "cancelled",
  "authorization_revoked",
]);

export const ticketBulkApi: TicketBulkApi = {
  async request({ body, csrfToken, idempotencyKey, tenantId }) {
    requireMutationContext(csrfToken, idempotencyKey, tenantId);
    validateBulkRequest(body);
    const result = await requestTenantTicketBulkJob({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    const projected = projectMutation(unwrap(result), tenantId, body.kind);
    validateRequestReceipt(projected.job, body);
    requirePrivateResponse(result.response, 202);
    const expectedLocation = `/api/v1/tenants/${tenantId}/ticket-bulk-jobs/${projected.job.id}`;
    if (result.response?.headers.get("Location") !== expectedLocation) {
      throw projectionMismatch(
        "The bulk-job creation location was not canonical.",
      );
    }
    return projected;
  },

  async get({ jobId, kind, signal, tenantId }) {
    canonicalUUIDv7(tenantId);
    canonicalUUIDv7(jobId);
    ticketKind(kind);
    const result = await getTenantTicketBulkJob({
      ...sameOrigin,
      path: { jobId, tenantId },
      query: { kind },
      ...(signal ? { signal } : {}),
    });
    const projected = projectJob(unwrap(result), tenantId, kind, jobId);
    requirePrivateResponse(result.response, 200);
    return projected;
  },

  async cancel({
    csrfToken,
    expectedRevision,
    idempotencyKey,
    jobId,
    kind,
    tenantId,
  }) {
    requireMutationContext(csrfToken, idempotencyKey, tenantId);
    canonicalUUIDv7(jobId);
    ticketKind(kind);
    resourceVersion(expectedRevision);
    const result = await cancelTenantTicketBulkJob({
      ...sameOrigin,
      body: { expectedRevision, kind },
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { jobId, tenantId },
    });
    const projected = projectMutation(unwrap(result), tenantId, kind, jobId);
    validateCancellationReceipt(projected.job, expectedRevision);
    requirePrivateResponse(result.response, 200);
    return projected;
  },

  async listResults({ after, jobId, kind, limit = 50, signal, tenantId }) {
    canonicalUUIDv7(tenantId);
    canonicalUUIDv7(jobId);
    ticketKind(kind);
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      (after !== undefined && !cursorPattern.test(after))
    ) {
      throw projectionMismatch(
        "The bulk-result page request was not canonical.",
      );
    }
    const result = await listTenantTicketBulkJobResults({
      ...sameOrigin,
      path: { jobId, tenantId },
      query: { kind, limit, ...(after ? { after } : {}) },
      ...(signal ? { signal } : {}),
    });
    const projected = projectResultPage(unwrap(result));
    requirePrivateResponse(result.response, 200);
    return projected;
  },
};

function validateBulkRequest(body: TicketBulkJobRequest): void {
  exactKeys(
    asRecord(body),
    ["kind", "mutation", "retentionSeconds", "selection"],
    ["kind", "mutation", "selection"],
  );
  if (body.kind !== "alert" && body.kind !== "case") throw projectionMismatch();
  const retention = body.retentionSeconds;
  if (
    retention !== undefined &&
    (!Number.isSafeInteger(retention) ||
      retention < 300 ||
      retention > 2_592_000)
  ) {
    throw projectionMismatch(
      "The bulk-job retention was outside the bounded contract.",
    );
  }
  const selection = body.selection;
  if (selection.source === "explicit") {
    exactKeys(
      asRecord(selection),
      ["query", "source", "targets"],
      ["source", "targets"],
    );
    if (
      selection.query !== undefined ||
      !Array.isArray(selection.targets) ||
      selection.targets.length < 1 ||
      selection.targets.length > 1_000
    ) {
      throw projectionMismatch(
        "The explicit bulk selection was not canonical.",
      );
    }
    const seen = new Set<string>();
    for (const target of selection.targets) {
      exactKeys(
        asRecord(target),
        ["expectedVersion", "id"],
        ["expectedVersion", "id"],
      );
      canonicalUUIDv7(target.id);
      resourceVersion(target.expectedVersion);
      if (seen.has(target.id))
        throw projectionMismatch(
          "The explicit bulk selection contained a duplicate target.",
        );
      seen.add(target.id);
    }
  } else if (selection.source === "query") {
    exactKeys(
      asRecord(selection),
      ["query", "source", "targets"],
      ["query", "source"],
    );
    if (selection.targets !== undefined || !selection.query)
      throw projectionMismatch();
    if (selection.query.source === "inline") {
      exactKeys(
        asRecord(selection.query),
        ["savedView", "source", "spec"],
        ["source", "spec"],
      );
      if (
        !selection.query.spec ||
        selection.query.savedView !== undefined ||
        !isSavedTicketViewSpecInput(selection.query.spec)
      )
        throw projectionMismatch();
    } else if (selection.query.source === "saved_view") {
      exactKeys(
        asRecord(selection.query),
        ["savedView", "source", "spec"],
        ["savedView", "source"],
      );
      const saved = selection.query.savedView;
      if (!saved || selection.query.spec !== undefined)
        throw projectionMismatch();
      exactKeys(
        asRecord(saved),
        ["expectedRevision", "expectedSpecSha256", "id"],
        ["expectedRevision", "expectedSpecSha256", "id"],
      );
      canonicalUUIDv7(saved.id);
      resourceVersion(saved.expectedRevision);
      canonicalDigest(saved.expectedSpecSha256);
    } else {
      throw projectionMismatch();
    }
  } else {
    throw projectionMismatch();
  }
  validateMutation(body.mutation);
}

function validateMutation(value: TicketBulkMutationRequest): void {
  const record = asRecord(value);
  exactKeys(
    record,
    ["action", "assigneeId", "teamId", "to", "transition"],
    ["action"],
  );
  switch (value.action) {
    case "transition":
      if (
        typeof value.transition !== "string" ||
        !workflowKeyPattern.test(value.transition) ||
        typeof value.to !== "string" ||
        !workflowKeyPattern.test(value.to) ||
        value.teamId !== undefined ||
        value.assigneeId !== undefined
      )
        throw projectionMismatch();
      return;
    case "assign":
    case "transfer":
      if (
        !value.teamId ||
        value.transition !== undefined ||
        value.to !== undefined
      )
        throw projectionMismatch();
      canonicalUUIDv7(value.teamId);
      if (value.assigneeId !== undefined) canonicalUUIDv7(value.assigneeId);
      return;
    case "claim":
      if (
        !value.teamId ||
        value.assigneeId !== undefined ||
        value.transition !== undefined ||
        value.to !== undefined
      )
        throw projectionMismatch();
      canonicalUUIDv7(value.teamId);
      return;
    case "release":
      if (
        value.teamId !== undefined ||
        value.assigneeId !== undefined ||
        value.transition !== undefined ||
        value.to !== undefined
      )
        throw projectionMismatch();
      return;
    default:
      throw projectionMismatch();
  }
}

function validateRequestReceipt(
  job: TicketBulkJobView,
  request: TicketBulkJobRequest,
): void {
  const requestedAt = parseRfc3339Instant(job.requestedAt);
  const updatedAt = parseRfc3339Instant(job.updatedAt);
  const availableAt = parseRfc3339Instant(job.availableAt);
  const expiresAt = parseRfc3339Instant(job.expiresAt);
  const expectedRetention =
    BigInt(request.retentionSeconds ?? defaultRetentionSeconds) *
    1_000_000_000n;
  if (
    job.state !== "pending" ||
    job.revision !== 1 ||
    job.activeBatch ||
    job.terminalAt !== undefined ||
    requestedAt === undefined ||
    updatedAt !== requestedAt ||
    availableAt !== requestedAt ||
    expiresAt === undefined ||
    expiresAt - requestedAt !== expectedRetention ||
    !sameBulkMutation(job.mutation, request.mutation)
  ) {
    throw projectionMismatch("The bulk-job receipt did not match the request.");
  }
  const selection = request.selection;
  if (selection.source === "explicit") {
    if (selection.targets === undefined) {
      throw projectionMismatch(
        "The bulk-job receipt did not bind the explicit targets.",
      );
    }
    const expected = [...selection.targets].toSorted((left, right) =>
      left.id.localeCompare(right.id, "en"),
    );
    const actual = job.selection.targets;
    if (
      job.selection.source !== "explicit" ||
      job.selection.targetCount !== expected.length ||
      actual?.length !== expected.length ||
      expected.some(
        (target, index) =>
          actual[index]?.id !== target.id ||
          actual[index]?.expectedVersion !== target.expectedVersion,
      )
    ) {
      throw projectionMismatch(
        "The bulk-job receipt did not bind the explicit targets.",
      );
    }
    return;
  }
  const query = selection.query;
  if (query === undefined) {
    throw projectionMismatch("The bulk-job receipt did not bind the query.");
  }
  if (
    job.selection.source !== "query" ||
    job.selection.querySource !== query.source ||
    job.selection.targets !== undefined
  ) {
    throw projectionMismatch("The bulk-job receipt did not bind the query.");
  }
  if (query.source === "inline") {
    if (job.selection.savedView !== undefined) {
      throw projectionMismatch("The bulk-job receipt did not bind the query.");
    }
    return;
  }
  const receipt = job.selection.savedView;
  const requestedSavedView = query.savedView;
  if (
    receipt === undefined ||
    requestedSavedView === undefined ||
    receipt.id !== requestedSavedView.id ||
    receipt.revision !== requestedSavedView.expectedRevision ||
    receipt.specSha256 !== requestedSavedView.expectedSpecSha256 ||
    job.selection.querySha256 !== requestedSavedView.expectedSpecSha256
  ) {
    throw projectionMismatch(
      "The bulk-job receipt did not bind the saved view.",
    );
  }
}

function validateCancellationReceipt(
  job: TicketBulkJobView,
  expectedRevision: number,
): void {
  if (
    job.revision !== expectedRevision + 1 ||
    (job.state !== "cancelled" && job.state !== "cancellation_requested")
  ) {
    throw projectionMismatch(
      "The bulk-job cancellation receipt was not canonical.",
    );
  }
}

function sameBulkMutation(
  left: TicketBulkMutationRequest,
  right: TicketBulkMutationRequest,
): boolean {
  return (
    left.action === right.action &&
    left.teamId === right.teamId &&
    left.assigneeId === right.assigneeId &&
    left.transition === right.transition &&
    left.to === right.to
  );
}

function projectMutation(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
  jobId?: string,
): TicketBulkMutationView {
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
): TicketBulkJobView {
  const record = exactRecord(
    value,
    [
      "activeBatch",
      "availableAt",
      "expiresAt",
      "id",
      "kind",
      "mutation",
      "ownerMembershipId",
      "progress",
      "requestedAt",
      "requesterUserId",
      "revision",
      "selection",
      "state",
      "tenantId",
      "terminalAt",
      "updatedAt",
    ],
    [
      "activeBatch",
      "availableAt",
      "expiresAt",
      "id",
      "kind",
      "mutation",
      "ownerMembershipId",
      "progress",
      "requestedAt",
      "requesterUserId",
      "revision",
      "selection",
      "state",
      "tenantId",
      "updatedAt",
    ],
  );
  if (
    record["tenantId"] !== tenantId ||
    record["kind"] !== kind ||
    typeof record["id"] !== "string" ||
    (expectedJobId !== undefined && record["id"] !== expectedJobId) ||
    typeof record["requesterUserId"] !== "string" ||
    typeof record["ownerMembershipId"] !== "string"
  )
    throw projectionMismatch();
  const id = canonicalUUIDv7(record["id"]);
  const requesterUserId = canonicalUUIDv7(record["requesterUserId"]);
  const ownerMembershipId = canonicalUUIDv7(record["ownerMembershipId"]);
  const revision = resourceVersion(record["revision"]);
  const state = record["state"];
  if (!isBulkState(state) || typeof record["activeBatch"] !== "boolean")
    throw projectionMismatch();
  const requested = projectedInstant(record["requestedAt"]),
    updated = projectedInstant(record["updatedAt"]);
  const available = projectedInstant(record["availableAt"]),
    expires = projectedInstant(record["expiresAt"]);
  if (
    updated.value < requested.value ||
    available.value < requested.value ||
    available.value > expires.value ||
    expires.value <= requested.value
  )
    throw projectionMismatch();
  const terminal = terminalStates.has(state);
  if (
    terminal !== (record["terminalAt"] !== undefined) ||
    record["activeBatch"] !==
      (state === "running" || state === "cancellation_requested")
  )
    throw projectionMismatch();
  const terminalAt =
    record["terminalAt"] === undefined
      ? undefined
      : projectedInstant(record["terminalAt"]);
  if (terminal && terminalAt?.value !== updated.value)
    throw projectionMismatch();
  const selection = projectSelection(record["selection"]);
  const progress = projectProgress(
    record["progress"],
    selection.targetCount,
    terminal,
  );
  const mutation = projectMutationShape(record["mutation"]);
  return {
    activeBatch: record["activeBatch"],
    availableAt: available.text,
    expiresAt: expires.text,
    id,
    kind,
    mutation,
    ownerMembershipId,
    progress,
    requestedAt: requested.text,
    requesterUserId,
    revision,
    selection,
    state,
    tenantId,
    updatedAt: updated.text,
    ...(terminalAt === undefined ? {} : { terminalAt: terminalAt.text }),
  };
}

function projectSelection(value: unknown): TicketBulkSelectionView {
  const record = asRecord(value);
  if (record["source"] === "explicit") {
    exactKeys(
      record,
      ["source", "targetCount", "targetSetSha256", "targets"],
      ["source", "targetCount", "targetSetSha256", "targets"],
    );
    const count = boundedCount(record["targetCount"]);
    const targetSetSha256 = canonicalDigest(record["targetSetSha256"]);
    const targetValues = record["targets"];
    if (
      !Array.isArray(targetValues) ||
      targetValues.length !== count ||
      count > 1_000
    )
      throw projectionMismatch();
    let previous = "";
    const targets: TicketBulkTargetPin[] = [];
    for (const targetValue of targetValues) {
      const target = exactRecord(
        targetValue,
        ["id", "expectedVersion"],
        ["id", "expectedVersion"],
      );
      if (typeof target["id"] !== "string") throw projectionMismatch();
      const id = canonicalUUIDv7(target["id"]);
      const expectedVersion = resourceVersion(target["expectedVersion"]);
      if (target["id"] <= previous)
        throw projectionMismatch(
          "The explicit target receipt was not canonical.",
        );
      previous = target["id"];
      targets.push({ id, expectedVersion });
    }
    return {
      source: "explicit",
      targetCount: count,
      targetSetSha256,
      targets,
    };
  }
  if (record["source"] !== "query") throw projectionMismatch();
  exactKeys(
    record,
    [
      "catalogSha256",
      "effectiveSpec",
      "querySha256",
      "querySource",
      "savedView",
      "source",
      "targetCount",
      "targetSetSha256",
    ],
    [
      "catalogSha256",
      "effectiveSpec",
      "querySha256",
      "querySource",
      "source",
      "targetCount",
      "targetSetSha256",
    ],
  );
  const count = boundedCount(record["targetCount"]);
  const targetSetSha256 = canonicalDigest(record["targetSetSha256"]);
  const querySha256 = canonicalDigest(record["querySha256"]);
  const catalogSha256 = canonicalDigest(record["catalogSha256"]);
  if (
    !isRecord(record["effectiveSpec"]) ||
    (record["querySource"] !== "inline" &&
      record["querySource"] !== "saved_view")
  )
    throw projectionMismatch();
  const result: TicketBulkSelectionView = {
    source: "query",
    targetCount: count,
    targetSetSha256,
    querySource: record["querySource"],
    querySha256,
    catalogSha256,
  };
  if (record["querySource"] === "saved_view") {
    const saved = exactRecord(
      record["savedView"],
      ["id", "ownerMembershipId", "revision", "specSha256"],
      ["id", "ownerMembershipId", "revision", "specSha256"],
    );
    if (
      typeof saved["id"] !== "string" ||
      typeof saved["ownerMembershipId"] !== "string"
    )
      throw projectionMismatch();
    const id = canonicalUUIDv7(saved["id"]);
    const ownerMembershipId = canonicalUUIDv7(saved["ownerMembershipId"]);
    const revision = resourceVersion(saved["revision"]);
    const specSha256 = canonicalDigest(saved["specSha256"]);
    result.savedView = {
      id,
      ownerMembershipId,
      revision,
      specSha256,
    };
  } else if (record["savedView"] !== undefined) {
    throw projectionMismatch();
  }
  return result;
}

function projectProgress(
  value: unknown,
  total: number,
  terminal: boolean,
): TicketBulkProgress {
  const keys = [
    "authorizationDenied",
    "authorizationRevoked",
    "cancelled",
    "internalFailure",
    "noChange",
    "notFoundOrHidden",
    "rejected",
    "succeeded",
    "total",
    "versionConflict",
  ];
  const record = exactRecord(value, keys, keys);
  const projected: TicketBulkProgress = {
    authorizationDenied: boundedCount(record["authorizationDenied"], true),
    authorizationRevoked: boundedCount(record["authorizationRevoked"], true),
    cancelled: boundedCount(record["cancelled"], true),
    internalFailure: boundedCount(record["internalFailure"], true),
    noChange: boundedCount(record["noChange"], true),
    notFoundOrHidden: boundedCount(record["notFoundOrHidden"], true),
    rejected: boundedCount(record["rejected"], true),
    succeeded: boundedCount(record["succeeded"], true),
    total: boundedCount(record["total"]),
    versionConflict: boundedCount(record["versionConflict"], true),
  };
  const processed =
    projected.succeeded +
    projected.noChange +
    projected.versionConflict +
    projected.notFoundOrHidden +
    projected.authorizationDenied +
    projected.rejected +
    projected.cancelled +
    projected.authorizationRevoked +
    projected.internalFailure;
  if (
    projected.total !== total ||
    processed > total ||
    terminal !== (processed === total)
  )
    throw projectionMismatch();
  return projected;
}

function projectMutationShape(value: unknown): TicketBulkMutationRequest {
  const record = exactRecord(
    value,
    ["action", "assigneeId", "teamId", "to", "transition"],
    ["action"],
  );
  switch (record["action"]) {
    case "transition":
      if (
        typeof record["transition"] !== "string" ||
        typeof record["to"] !== "string" ||
        record["teamId"] !== undefined ||
        record["assigneeId"] !== undefined
      )
        throw projectionMismatch();
      return {
        action: "transition",
        transition: record["transition"],
        to: record["to"],
      };
    case "assign":
    case "transfer": {
      const teamId = canonicalUUIDv7(record["teamId"]);
      const assigneeId =
        record["assigneeId"] === undefined
          ? undefined
          : canonicalUUIDv7(record["assigneeId"]);
      if (record["transition"] !== undefined || record["to"] !== undefined)
        throw projectionMismatch();
      return {
        action: record["action"],
        teamId,
        ...(assigneeId === undefined ? {} : { assigneeId }),
      };
    }
    case "claim":
      if (
        record["assigneeId"] !== undefined ||
        record["transition"] !== undefined ||
        record["to"] !== undefined
      )
        throw projectionMismatch();
      return { action: "claim", teamId: canonicalUUIDv7(record["teamId"]) };
    case "release":
      if (
        record["assigneeId"] !== undefined ||
        record["teamId"] !== undefined ||
        record["transition"] !== undefined ||
        record["to"] !== undefined
      )
        throw projectionMismatch();
      return { action: "release" };
    default:
      throw projectionMismatch();
  }
}

function projectResultPage(value: unknown): TicketBulkResultPageView {
  const record = exactRecord(value, ["items", "nextCursor"], ["items"]);
  if (
    !Array.isArray(record["items"]) ||
    record["items"].length > 100 ||
    (record["nextCursor"] !== undefined &&
      (typeof record["nextCursor"] !== "string" ||
        !cursorPattern.test(record["nextCursor"])))
  )
    throw projectionMismatch();
  let previous = 0;
  const items = record["items"].map((itemValue): TicketBulkTargetResultView => {
    const item = exactRecord(
      itemValue,
      ["recordedAt", "result", "sequence", "targetId", "targetVersion"],
      ["recordedAt", "result", "sequence", "targetId", "targetVersion"],
    );
    const sequence = boundedCount(item["sequence"]);
    const result = resultCode(item["result"]);
    if (sequence <= previous) throw projectionMismatch();
    previous = sequence;
    const targetId = canonicalUUIDv7(item["targetId"]);
    const targetVersion = resourceVersion(item["targetVersion"]);
    const recordedAt = projectedInstant(item["recordedAt"]).text;
    return {
      recordedAt,
      result,
      sequence,
      targetId,
      targetVersion,
    };
  });
  const nextCursor = record["nextCursor"];
  return {
    items,
    ...(nextCursor === undefined ? {} : { nextCursor }),
  };
}

function isBulkState(value: unknown): value is TicketBulkState {
  return (
    value === "pending" ||
    value === "running" ||
    value === "cancellation_requested" ||
    value === "completed" ||
    value === "failed" ||
    value === "cancelled" ||
    value === "authorization_revoked"
  );
}

function boundedCount(value: unknown, allowZero = false): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > 100_000
  )
    throw projectionMismatch();
  return value;
}

function projectedInstant(value: unknown): { text: string; value: bigint } {
  if (typeof value !== "string")
    throw projectionMismatch("The bulk-job timestamp was not canonical.");
  const parsed = parseRfc3339Instant(value);
  if (parsed === undefined)
    throw projectionMismatch("The bulk-job timestamp was not canonical.");
  return { text: value, value: parsed };
}

function requireMutationContext(
  csrfToken: string,
  idempotencyKey: string,
  tenantId: string,
): void {
  canonicalUUIDv7(tenantId);
  if (csrfToken.trim() === "" || !idempotencyKeyPattern.test(idempotencyKey))
    throw projectionMismatch();
}

function ticketKind(value: unknown): TicketKind {
  if (value !== "alert" && value !== "case") throw projectionMismatch();
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
      "The bulk-job response was not private and canonical.",
    );
  }
}

function resourceVersion(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 2_147_483_647
  )
    throw projectionMismatch();
  return value;
}

function canonicalUUIDv7(value: unknown): string {
  if (typeof value !== "string" || !uuidV7Pattern.test(value))
    throw projectionMismatch("A canonical UUIDv7 identifier is required.");
  return value;
}

function canonicalDigest(value: unknown): string {
  if (
    typeof value !== "string" ||
    !sha256Pattern.test(value) ||
    /^0+$/u.test(value)
  )
    throw projectionMismatch("A canonical SHA-256 receipt is required.");
  return value;
}

function resultCode(value: unknown): TicketBulkTargetResultCode {
  if (
    value !== "succeeded" &&
    value !== "no_change" &&
    value !== "version_conflict" &&
    value !== "not_found_or_hidden" &&
    value !== "authorization_denied" &&
    value !== "rejected" &&
    value !== "cancelled" &&
    value !== "authorization_revoked" &&
    value !== "internal_failure"
  )
    throw projectionMismatch();
  return value;
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
  record: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
): void {
  const allowedSet = new Set(allowed);
  if (
    Object.keys(record).some((key) => !allowedSet.has(key)) ||
    required.some((key) => !(key in record))
  )
    throw projectionMismatch();
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
  const detail =
    typeof problem?.["detail"] === "string" ? problem["detail"] : undefined;
  const title =
    typeof problem?.["title"] === "string" ? problem["title"] : undefined;
  const code =
    typeof problem?.["code"] === "string" ? problem["code"] : undefined;
  const requestId =
    typeof problem?.["requestId"] === "string"
      ? problem["requestId"]
      : undefined;
  throw new TicketingApiError(
    (detail ?? title ?? "The bulk operation could not be completed.").slice(
      0,
      320,
    ),
    result.response?.status,
    code,
    requestId,
  );
}

function projectionMismatch(
  message = "The bulk-job projection was not safe to display.",
): TicketingApiError {
  return new TicketingApiError(message, undefined, "projection_mismatch");
}
