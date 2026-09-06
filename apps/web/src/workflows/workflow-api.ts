import {
  archiveTenantWorkflow,
  createTenantWorkflow,
  getTenantWorkflow,
  listTenantWorkflows,
  listTenantWorkflowVersions,
  publishTenantWorkflowVersion,
  restoreTenantWorkflow,
  setDefaultTenantWorkflow,
  simulateTenantWorkflow,
  updateTenantWorkflowMetadata,
  type WorkflowDesign as ContractWorkflowDesign,
  type WorkflowSimulationRequest as ContractWorkflowSimulationRequest,
} from "@periapsis/contracts";
import { z } from "zod";

import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  boundedWorkflowText,
  normalizeWorkflowCatalogKey,
  normalizeWorkflowDesign,
  workflowConditionValueType,
  workflowPermissionOrder,
  type ManagedWorkflow,
  type WorkflowCondition,
  type WorkflowConditionValue,
  type WorkflowDesign,
  type WorkflowEffect,
  type WorkflowKind,
  type WorkflowPermission,
  type WorkflowSimulationRequest,
  type WorkflowSimulationResult,
  type WorkflowStatus,
  type WorkflowVersion,
} from "./model";

export interface WorkflowPage {
  items: ManagedWorkflow[];
  nextCursor?: string | undefined;
}

export interface WorkflowVersionPage {
  items: WorkflowVersion[];
  nextVersion?: number | undefined;
}

export interface VersionedWorkflow {
  etag: string;
  replayed: boolean;
  value: ManagedWorkflow;
}

export interface WorkflowAdministrationApi {
  list(input: {
    after?: string | undefined;
    defaultOnly?: boolean | undefined;
    kind: WorkflowKind;
    limit?: number | undefined;
    search?: string | undefined;
    signal?: AbortSignal | undefined;
    status?: WorkflowStatus | undefined;
    tenantId: string;
  }): Promise<WorkflowPage>;
  get(input: {
    signal?: AbortSignal | undefined;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  create(input: {
    body: {
      kind: WorkflowKind;
      key: string;
      displayName: string;
      description: string;
      design: WorkflowDesign;
    };
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<VersionedWorkflow>;
  publish(input: {
    body: { expectedRevision: number; design: WorkflowDesign };
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  updateMetadata(input: {
    body: {
      expectedRevision: number;
      displayName: string;
      description: string;
    };
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  setDefault(input: {
    body: { expectedRevision: number };
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  archive(input: {
    body: { expectedRevision: number };
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  restore(input: {
    body: { expectedRevision: number };
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    workflowId: string;
  }): Promise<VersionedWorkflow>;
  listVersions(input: {
    afterVersion?: number | undefined;
    limit?: number | undefined;
    signal?: AbortSignal | undefined;
    tenantId: string;
    workflowId: string;
  }): Promise<WorkflowVersionPage>;
  simulate(input: {
    body: WorkflowSimulationRequest;
    csrfToken: string;
    tenantId: string;
    workflowId: string;
  }): Promise<WorkflowSimulationResult>;
}

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

interface MutationContext {
  csrfToken: string;
  idempotencyKey: string;
  tenantId: string;
}

interface VersionMutationContext extends MutationContext {
  body: { expectedRevision: number };
  etag: string;
  workflowId: string;
}

const maximumResourceVersion = 2_147_483_647;
const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const cursorPattern = /^[A-Za-z0-9_-]{1,512}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const workflowStrongEntityTagPattern =
  /^"v([1-9]\d{0,9})-([A-Za-z0-9_-]{43})"$/u;
const keyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const conditionFieldPattern =
  /^(?:aggregate_kind|state|severity|priority|category|classification|source|source_type|customer_visible|assigned|assignee_present|claimed|comment_present|detected_at|received_at|opened_at|created_at|updated_at|(?:custom|tag)\.[a-z][a-z0-9_.-]{0,63})$/u;
const effectOrder: readonly WorkflowEffect[] = [
  "activity",
  "audit",
  "sla",
  "notification",
];
const forbiddenProjectionKeys = new Set([
  "csrfToken",
  "idempotencyKey",
  "keyDigest",
  "password",
  "passwordCiphertext",
  "requestDigest",
  "secret",
  "secretCiphertext",
  "token",
]);

const effectSchema = z.enum(["activity", "audit", "sla", "notification"]);
const actionSchema = z.enum([
  "create",
  "assign",
  "claim",
  "release",
  "transfer",
  "escalate",
  "link",
]);
const permissionSchema = z.enum([
  "alert.create",
  "alert.update",
  "alert.assign",
  "alert.claim",
  "alert.escalate",
  "alert.comment.public",
  "alert.comment.private",
  "case.create",
  "case.update",
  "case.claim",
  "case.transfer",
  "case.transition",
  "case.comment.public",
  "case.comment.private",
]);
const conditionValueSchema: z.ZodType<WorkflowConditionValue> =
  z.discriminatedUnion("type", [
    z.strictObject({ type: z.literal("text"), value: z.string() }),
    z.strictObject({ type: z.literal("number"), value: z.number() }),
    z.strictObject({ type: z.literal("boolean"), value: z.boolean() }),
    z.strictObject({ type: z.literal("instant"), value: z.string() }),
  ]);
const conditionSchema: z.ZodType<WorkflowCondition> = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("predicate"),
      field: z.string(),
      operator: z.enum([
        "equal",
        "not_equal",
        "in",
        "not_in",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
        "exists",
        "not_exists",
      ]),
      values: z.array(conditionValueSchema).max(32),
    }),
    z.strictObject({
      kind: z.literal("all"),
      children: z.array(conditionSchema).min(2).max(32),
    }),
    z.strictObject({
      kind: z.literal("any"),
      children: z.array(conditionSchema).min(2).max(32),
    }),
    z.strictObject({
      kind: z.literal("not"),
      children: z.tuple([conditionSchema]),
    }),
  ]),
);
const stateSchema = z.strictObject({
  key: z.string().regex(keyPattern),
  initial: z.boolean(),
  terminal: z.boolean(),
  visibility: z.enum(["internal", "customer"]),
  actions: z
    .array(
      z.strictObject({
        action: actionSchema,
        effects: z.array(effectSchema).min(2).max(4),
      }),
    )
    .max(7),
});
const transitionSchema = z.strictObject({
  key: z.string().regex(keyPattern),
  from: z.string().regex(keyPattern),
  to: z.string().regex(keyPattern),
  requiredComment: z.boolean(),
  reopen: z.boolean(),
  requiredRoles: z.array(z.string().regex(keyPattern)).max(64),
  requiredPermissions: z.array(permissionSchema).max(64),
  requiredCustomFields: z.array(z.string().regex(keyPattern)).max(64),
  condition: conditionSchema.optional(),
  effects: z.array(effectSchema).min(2).max(4),
});
const designSchema = z.strictObject({
  states: z.array(stateSchema).min(2).max(64),
  transitions: z.array(transitionSchema).min(1).max(256),
});
const definitionSchema = z.strictObject({
  id: z.string().regex(uuidV7Pattern),
  kind: z.enum(["alert", "case"]),
  version: z.number().int().min(1).max(maximumResourceVersion),
  initialState: z.string().regex(keyPattern),
  states: z.array(stateSchema).min(2).max(64),
  transitions: z.array(transitionSchema).min(1).max(256),
});
const managedWorkflowSchema = z.strictObject({
  id: z.string().regex(uuidV7Pattern),
  tenantId: z.string().regex(uuidV7Pattern),
  kind: z.enum(["alert", "case"]),
  key: z.string().min(3).max(64),
  displayName: z.string().min(1).max(120),
  description: z.string().max(1000),
  isDefault: z.boolean(),
  status: z.enum(["active", "archived"]),
  revision: z.number().int().min(1).max(maximumResourceVersion),
  currentVersion: z.number().int().min(1).max(maximumResourceVersion),
  current: definitionSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  archivedAt: z.string().optional(),
});
const versionRecordSchema = z.strictObject({
  tenantId: z.string().regex(uuidV7Pattern),
  workflowId: z.string().regex(uuidV7Pattern),
  definition: definitionSchema,
  publishedByMembershipId: z.string().regex(uuidV7Pattern).optional(),
  publisherDisplayName: z.string().max(200),
  publishedAt: z.string(),
});
const simulationRequestSchema = z.strictObject({
  version: z.number().int().min(0).max(maximumResourceVersion),
  state: z.string().regex(keyPattern),
  commentPresent: z.boolean(),
  roles: z.array(z.string().regex(keyPattern)).max(64),
  permissions: z.array(permissionSchema).max(64),
  providedCustomFields: z.array(z.string().regex(keyPattern)).max(64),
  facts: z
    .array(
      z.strictObject({
        field: z.string().regex(conditionFieldPattern),
        value: conditionValueSchema.optional(),
      }),
    )
    .max(256),
});
const transitionSimulationSchema = z.strictObject({
  key: z.string().regex(keyPattern),
  from: z.string().regex(keyPattern),
  to: z.string().regex(keyPattern),
  reopen: z.boolean(),
  eligible: z.boolean(),
  gates: z.strictObject({
    commentSatisfied: z.boolean(),
    roleSatisfied: z.boolean(),
    permissionsSatisfied: z.boolean(),
    customFieldsSatisfied: z.boolean(),
    conditionSatisfied: z.boolean(),
  }),
  missingRoles: z.array(z.string().regex(keyPattern)).max(64),
  missingPermissions: z.array(permissionSchema).max(64),
  missingCustomFields: z.array(z.string().regex(keyPattern)).max(64),
  effects: z.array(effectSchema).min(2).max(4),
});
const simulationResultSchema = z.strictObject({
  workflowId: z.string().regex(uuidV7Pattern),
  kind: z.enum(["alert", "case"]),
  version: z.number().int().min(1).max(maximumResourceVersion),
  explanatory: z.literal(true),
  transitions: z.array(transitionSimulationSchema).max(256),
});

export const workflowAdministrationApi: WorkflowAdministrationApi = {
  async list({
    after,
    defaultOnly,
    kind,
    limit,
    search,
    signal,
    status,
    tenantId,
  }) {
    if (defaultOnly !== undefined && typeof defaultOnly !== "boolean") {
      throw new WorkflowApiError("The default workflow filter is invalid.");
    }
    const normalizedTenantId = requireUuid(tenantId, "tenant");
    const normalizedKind = requireKind(kind);
    const normalizedLimit = requirePageSize(limit);
    const normalizedAfter = requireCursor(after);
    const normalizedSearch = requireSearch(search);
    const normalizedStatus = requireStatus(status);
    const value = unwrap(
      await listTenantWorkflows({
        ...sameOrigin,
        path: { tenantId: normalizedTenantId },
        query: {
          limit: normalizedLimit,
          kind: normalizedKind,
          ...(normalizedAfter ? { after: normalizedAfter } : {}),
          ...(normalizedSearch ? { search: normalizedSearch } : {}),
          ...(normalizedStatus ? { status: normalizedStatus } : {}),
          ...(defaultOnly === undefined ? {} : { default: defaultOnly }),
        },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectWorkflowPage(value, {
      after: normalizedAfter,
      defaultOnly: defaultOnly === true,
      kind: normalizedKind,
      limit: normalizedLimit,
      status: normalizedStatus,
      tenantId: normalizedTenantId,
    });
  },

  async get({ signal, tenantId, workflowId }) {
    const normalizedTenantId = requireUuid(tenantId, "tenant");
    const normalizedWorkflowId = requireUuid(workflowId, "workflow");
    const result = await getTenantWorkflow({
      ...sameOrigin,
      path: {
        tenantId: normalizedTenantId,
        workflowId: normalizedWorkflowId,
      },
      ...(signal ? { signal } : {}),
    });
    return projectCurrentWorkflowResult(
      result,
      normalizedTenantId,
      normalizedWorkflowId,
    );
  },

  async create(input) {
    requireMutation(input);
    const body = normalizeCreateBody(input.body);
    const result = await createTenantWorkflow({
      ...sameOrigin,
      body: { ...body, design: toContractDesign(body.design) },
      headers: mutationHeaders(input),
      path: { tenantId: input.tenantId },
    });
    const projected = await projectMutationResult(result, {
      kind: body.kind,
      revision: 1,
      tenantId: input.tenantId,
    });
    if (
      projected.value.key !== body.key ||
      projected.value.displayName !== body.displayName ||
      projected.value.description !== body.description ||
      projected.value.currentVersion !== 1 ||
      projected.value.isDefault ||
      stableJson(workflowDesignOf(projected.value)) !== stableJson(body.design)
    ) {
      throw projectionMismatch();
    }
    return projected;
  },

  async publish(input) {
    await requireVersionMutation(input);
    const design = normalizeDesignInput(input.body.design);
    const result = await publishTenantWorkflowVersion({
      ...sameOrigin,
      body: {
        design: toContractDesign(design),
        expectedRevision: input.body.expectedRevision,
      },
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, workflowId: input.workflowId },
    });
    const projected = await projectMutationResult(result, {
      id: input.workflowId,
      revision: input.body.expectedRevision + 1,
      tenantId: input.tenantId,
    });
    if (
      projected.value.status !== "active" ||
      stableJson(workflowDesignOf(projected.value)) !== stableJson(design)
    ) {
      throw projectionMismatch();
    }
    return projected;
  },

  async updateMetadata(input) {
    await requireVersionMutation(input);
    const displayName = normalizeText(
      input.body.displayName,
      120,
      "workflow display name",
    );
    const description = normalizeText(
      input.body.description,
      1000,
      "workflow description",
      true,
    );
    const result = await updateTenantWorkflowMetadata({
      ...sameOrigin,
      body: {
        description,
        displayName,
        expectedRevision: input.body.expectedRevision,
      },
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, workflowId: input.workflowId },
    });
    const projected = await projectMutationResult(result, {
      id: input.workflowId,
      revision: input.body.expectedRevision + 1,
      tenantId: input.tenantId,
    });
    if (
      projected.value.displayName !== displayName ||
      projected.value.description !== description
    ) {
      throw projectionMismatch();
    }
    return projected;
  },

  async setDefault(input) {
    await requireVersionMutation(input);
    const result = await setDefaultTenantWorkflow({
      ...sameOrigin,
      body: { expectedRevision: input.body.expectedRevision },
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, workflowId: input.workflowId },
    });
    const projected = await projectMutationResult(result, {
      id: input.workflowId,
      revision: input.body.expectedRevision + 1,
      tenantId: input.tenantId,
    });
    if (!projected.value.isDefault || projected.value.status !== "active") {
      throw projectionMismatch();
    }
    return projected;
  },

  async archive(input) {
    await requireVersionMutation(input);
    const result = await archiveTenantWorkflow({
      ...sameOrigin,
      body: { expectedRevision: input.body.expectedRevision },
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, workflowId: input.workflowId },
    });
    const projected = await projectMutationResult(result, {
      id: input.workflowId,
      revision: input.body.expectedRevision + 1,
      tenantId: input.tenantId,
    });
    if (projected.value.status !== "archived" || projected.value.isDefault) {
      throw projectionMismatch();
    }
    return projected;
  },

  async restore(input) {
    await requireVersionMutation(input);
    const result = await restoreTenantWorkflow({
      ...sameOrigin,
      body: { expectedRevision: input.body.expectedRevision },
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, workflowId: input.workflowId },
    });
    const projected = await projectMutationResult(result, {
      id: input.workflowId,
      revision: input.body.expectedRevision + 1,
      tenantId: input.tenantId,
    });
    if (projected.value.status !== "active" || projected.value.isDefault) {
      throw projectionMismatch();
    }
    return projected;
  },

  async listVersions({ afterVersion, limit, signal, tenantId, workflowId }) {
    const normalizedTenantId = requireUuid(tenantId, "tenant");
    const normalizedWorkflowId = requireUuid(workflowId, "workflow");
    const normalizedLimit = requirePageSize(limit);
    const normalizedAfter =
      afterVersion === undefined
        ? undefined
        : requireResourceVersion(afterVersion, "history cursor");
    const value = unwrap(
      await listTenantWorkflowVersions({
        ...sameOrigin,
        path: {
          tenantId: normalizedTenantId,
          workflowId: normalizedWorkflowId,
        },
        query: {
          limit: normalizedLimit,
          ...(normalizedAfter === undefined
            ? {}
            : { afterVersion: normalizedAfter }),
        },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectVersionPage(value, {
      afterVersion: normalizedAfter,
      limit: normalizedLimit,
      tenantId: normalizedTenantId,
      workflowId: normalizedWorkflowId,
    });
  },

  async simulate({ body, csrfToken, tenantId, workflowId }) {
    const normalizedTenantId = requireUuid(tenantId, "tenant");
    const normalizedWorkflowId = requireUuid(workflowId, "workflow");
    requireCsrf(csrfToken);
    const normalizedBody = normalizeSimulationInput(body);
    const value = unwrap(
      await simulateTenantWorkflow({
        ...sameOrigin,
        body: toContractSimulationRequest(normalizedBody),
        headers: { "X-CSRF-Token": csrfToken },
        path: {
          tenantId: normalizedTenantId,
          workflowId: normalizedWorkflowId,
        },
      }),
    );
    return projectSimulationResult(value, normalizedWorkflowId, normalizedBody);
  },
};

function mutationHeaders(input: MutationContext) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "X-CSRF-Token": input.csrfToken,
  };
}

function versionHeaders(input: VersionMutationContext) {
  return { ...mutationHeaders(input), "If-Match": input.etag };
}

function requireMutation(input: MutationContext): void {
  requireUuid(input.tenantId, "tenant");
  requireCsrf(input.csrfToken);
  if (!idempotencyKeyPattern.test(input.idempotencyKey)) {
    throw new WorkflowApiError("A valid retry key is required.");
  }
}

async function requireVersionMutation(
  input: VersionMutationContext,
): Promise<void> {
  requireMutation(input);
  requireUuid(input.workflowId, "workflow");
  const revision = requireResourceVersion(
    input.body.expectedRevision,
    "expected revision",
  );
  await requireWorkflowEtag(input.etag, input.workflowId, revision, false);
}

function requireCsrf(value: string): void {
  if (!value.trim() || value.length > 4096 || value.includes(",")) {
    throw new WorkflowApiError("Request integrity context is unavailable.");
  }
}

function requireUuid(value: string, label: string): string {
  if (!uuidV7Pattern.test(value)) {
    throw new WorkflowApiError(`A canonical ${label} identifier is required.`);
  }
  return value;
}

function requireKind(value: WorkflowKind): WorkflowKind {
  if (value !== "alert" && value !== "case") {
    throw new WorkflowApiError("A supported workflow kind is required.");
  }
  return value;
}

function requireStatus(
  value: WorkflowStatus | undefined,
): WorkflowStatus | undefined {
  if (value !== undefined && value !== "active" && value !== "archived") {
    throw new WorkflowApiError("A supported workflow status is required.");
  }
  return value;
}

function requirePageSize(value: number | undefined): number {
  const limit = value ?? 50;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new WorkflowApiError("The workflow page size is invalid.");
  }
  return limit;
}

function requireCursor(value: string | undefined): string | undefined {
  if (value !== undefined && !cursorPattern.test(value)) {
    throw new WorkflowApiError("The workflow cursor is invalid.");
  }
  return value;
}

function requireSearch(value: string | undefined): string | undefined {
  if (
    value !== undefined &&
    (value.trim() !== value ||
      value.length < 1 ||
      new TextEncoder().encode(value).byteLength > 200 ||
      hasForbiddenText(value))
  ) {
    throw new WorkflowApiError("The workflow search is invalid.");
  }
  return value;
}

function requireResourceVersion(value: number, label: string): number {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximumResourceVersion
  ) {
    throw new WorkflowApiError(`The ${label} is invalid.`);
  }
  return value;
}

function normalizeCreateBody(input: {
  kind: WorkflowKind;
  key: string;
  displayName: string;
  description: string;
  design: WorkflowDesign;
}) {
  let key: string;
  try {
    key = normalizeWorkflowCatalogKey(input.key);
  } catch {
    throw new WorkflowApiError("The workflow key is invalid.");
  }
  const kind = requireKind(input.kind);
  return {
    kind,
    key,
    displayName: normalizeText(input.displayName, 120, "workflow display name"),
    description: normalizeText(
      input.description,
      1000,
      "workflow description",
      true,
    ),
    design: normalizeDesignInput(input.design, kind),
  };
}

function normalizeText(
  value: string,
  maximumBytes: number,
  label: string,
  optional = false,
): string {
  try {
    return boundedWorkflowText(value, maximumBytes, label, optional);
  } catch {
    throw new WorkflowApiError(`The ${label} is invalid.`);
  }
}

function normalizeDesignInput(
  value: WorkflowDesign,
  knownKind?: WorkflowKind,
): WorkflowDesign {
  const parsed = designSchema.safeParse(value);
  if (!parsed.success) {
    throw new WorkflowApiError("The workflow definition is invalid.");
  }
  const candidateKinds: readonly WorkflowKind[] = knownKind
    ? [knownKind]
    : inferDesignKinds(parsed.data);
  for (const kind of candidateKinds) {
    try {
      const normalized = normalizeWorkflowDesign(kind, parsed.data);
      validateDesignConditionValues(normalized);
      return normalized;
    } catch {
      // Try the other closed kind when the request does not carry kind.
    }
  }
  throw new WorkflowApiError("The workflow definition is invalid.");
}

function inferDesignKinds(design: WorkflowDesign): readonly WorkflowKind[] {
  const permissions = design.transitions.flatMap(
    (transition) => transition.requiredPermissions,
  );
  if (
    permissions.some((permission) => permission.startsWith("case.")) ||
    design.states.some((state) =>
      state.actions.some((action) => action.action === "link"),
    )
  ) {
    return ["case", "alert"];
  }
  return ["alert", "case"];
}

function normalizeSimulationInput(
  value: WorkflowSimulationRequest,
): WorkflowSimulationRequest {
  const parsed = simulationRequestSchema.safeParse(value);
  if (!parsed.success) {
    throw new WorkflowApiError("The workflow simulation input is invalid.");
  }
  if (
    !isCanonicalUnique(parsed.data.roles) ||
    !isCanonicalPermissions(parsed.data.permissions) ||
    !isCanonicalUnique(parsed.data.providedCustomFields) ||
    !isCanonicalUnique(parsed.data.facts.map((fact) => fact.field))
  ) {
    throw new WorkflowApiError("The workflow simulation input is invalid.");
  }
  for (const fact of parsed.data.facts) {
    if (fact.value) {
      validateConditionValue(fact.value);
      const expected = workflowConditionValueType(fact.field);
      if (expected !== undefined && fact.value.type !== expected) {
        throw new WorkflowApiError("The workflow simulation input is invalid.");
      }
    }
    if (
      fact.field === "state" &&
      (fact.value?.type !== "text" || fact.value.value !== parsed.data.state)
    ) {
      throw new WorkflowApiError("The workflow simulation input is invalid.");
    }
  }
  return parsed.data;
}

function toContractDesign(value: WorkflowDesign): ContractWorkflowDesign {
  return {
    states: value.states.map((state) => ({
      ...state,
      actions: state.actions.map((action) => ({ ...action })),
    })),
    transitions: value.transitions.map(({ condition, ...transition }) => ({
      ...transition,
      ...(condition === undefined ? {} : { condition }),
    })),
  };
}

function toContractSimulationRequest(
  value: WorkflowSimulationRequest,
): ContractWorkflowSimulationRequest {
  return {
    ...value,
    facts: value.facts.map(({ value: factValue, ...fact }) => ({
      ...fact,
      ...(factValue === undefined ? {} : { value: factValue }),
    })),
  };
}

function validateConditionValue(value: WorkflowConditionValue): void {
  if (
    (value.type === "text" &&
      (value.value.trim() !== value.value ||
        value.value.length === 0 ||
        new TextEncoder().encode(value.value).byteLength > 2048 ||
        hasForbiddenText(value.value))) ||
    (value.type === "number" && !Number.isFinite(value.value)) ||
    (value.type === "instant" && parseRfc3339Instant(value.value) === undefined)
  ) {
    throw new WorkflowApiError("A workflow condition value is invalid.");
  }
}

function validateDesignConditionValues(design: WorkflowDesign): void {
  for (const transition of design.transitions) {
    if (transition.condition) {
      validateConditionNodeValues(transition.condition);
    }
  }
}

function validateConditionNodeValues(condition: WorkflowCondition): void {
  if (condition.kind === "predicate") {
    for (const value of condition.values) validateConditionValue(value);
    return;
  }
  for (const child of condition.children) validateConditionNodeValues(child);
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (
    result.data !== undefined &&
    result.error === undefined &&
    result.response?.ok !== false
  ) {
    return result.data;
  }
  throw toWorkflowApiError(result.response);
}

async function projectCurrentWorkflowResult<T>(
  result: GeneratedResult<T>,
  tenantId: string,
  workflowId: string,
): Promise<VersionedWorkflow> {
  const value = projectManagedWorkflow(unwrap(result), tenantId, workflowId);
  const etag = result.response?.headers.get("ETag");
  await requireWorkflowEtag(etag, value.id, value.revision, true);
  return { etag: etag!, replayed: false, value };
}

async function projectMutationResult<T>(
  result: GeneratedResult<T>,
  expected: {
    id?: string | undefined;
    kind?: WorkflowKind | undefined;
    revision: number;
    tenantId: string;
  },
): Promise<VersionedWorkflow> {
  const raw = unwrap(result);
  assertBoundedProjection(raw);
  const envelope = z
    .strictObject({ workflow: managedWorkflowSchema, replayed: z.boolean() })
    .safeParse(raw);
  if (!envelope.success) throw projectionMismatch();
  const value = projectManagedWorkflow(
    envelope.data.workflow,
    expected.tenantId,
    expected.id,
    expected.kind,
  );
  if (value.revision !== expected.revision) throw projectionMismatch();
  const etag = result.response?.headers.get("ETag");
  await requireWorkflowEtag(etag, value.id, value.revision, true);
  return { etag: etag!, replayed: envelope.data.replayed, value };
}

function projectWorkflowPage(
  value: unknown,
  expected: {
    after?: string | undefined;
    defaultOnly: boolean;
    kind: WorkflowKind;
    limit: number;
    status?: WorkflowStatus | undefined;
    tenantId: string;
  },
): WorkflowPage {
  assertBoundedProjection(value);
  const parsed = z
    .strictObject({
      items: z.array(managedWorkflowSchema).max(100),
      nextCursor: z.string().regex(cursorPattern).optional(),
    })
    .safeParse(value);
  if (!parsed.success) throw projectionMismatch();
  if (
    parsed.data.items.length > expected.limit ||
    (parsed.data.items.length === 0 && parsed.data.nextCursor !== undefined) ||
    (expected.after !== undefined && parsed.data.nextCursor === expected.after)
  ) {
    throw projectionMismatch();
  }
  const items = parsed.data.items.map((item) =>
    projectManagedWorkflow(item, expected.tenantId, undefined, expected.kind),
  );
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index]!;
    if (
      (expected.status !== undefined && item.status !== expected.status) ||
      (expected.defaultOnly && !item.isDefault) ||
      (index > 0 && items[index - 1]!.id >= item.id)
    ) {
      throw projectionMismatch();
    }
  }
  return {
    items,
    ...(parsed.data.nextCursor ? { nextCursor: parsed.data.nextCursor } : {}),
  };
}

function projectManagedWorkflow(
  value: unknown,
  tenantId: string,
  workflowId?: string,
  kind?: WorkflowKind,
): ManagedWorkflow {
  assertBoundedProjection(value);
  const parsed = managedWorkflowSchema.safeParse(value);
  if (!parsed.success) throw projectionMismatch();
  const workflow = parsed.data;
  let canonicalDesign: WorkflowDesign;
  try {
    canonicalDesign = normalizeWorkflowDesign(
      workflow.kind,
      workflowDesignOf(workflow),
    );
    validateDesignConditionValues(canonicalDesign);
  } catch {
    throw projectionMismatch();
  }
  const createdAt = parseRfc3339Instant(workflow.createdAt);
  const updatedAt = parseRfc3339Instant(workflow.updatedAt);
  const archivedAt =
    workflow.archivedAt === undefined
      ? undefined
      : parseRfc3339Instant(workflow.archivedAt);
  let normalizedKey: string | undefined;
  try {
    normalizedKey = normalizeWorkflowCatalogKey(workflow.key);
  } catch {
    normalizedKey = undefined;
  }
  if (
    workflow.tenantId !== tenantId ||
    (workflowId !== undefined && workflow.id !== workflowId) ||
    (kind !== undefined && workflow.kind !== kind) ||
    workflow.current.id !== workflow.id ||
    workflow.current.kind !== workflow.kind ||
    workflow.current.version !== workflow.currentVersion ||
    workflow.current.initialState !==
      workflow.current.states.find((state) => state.initial)?.key ||
    normalizedKey !== workflow.key ||
    normalizeTextProjection(workflow.displayName, 120, false) !==
      workflow.displayName ||
    normalizeTextProjection(workflow.description, 1000, true) !==
      workflow.description ||
    stableJson(workflowDesignOf(workflow)) !== stableJson(canonicalDesign) ||
    createdAt === undefined ||
    updatedAt === undefined ||
    createdAt > updatedAt ||
    (workflow.status === "active" && workflow.archivedAt !== undefined) ||
    (workflow.status === "archived" &&
      (archivedAt === undefined ||
        archivedAt < createdAt ||
        archivedAt > updatedAt)) ||
    (workflow.isDefault && workflow.status !== "active")
  ) {
    throw projectionMismatch();
  }
  return {
    ...workflow,
    current: { ...workflow.current, ...canonicalDesign },
  };
}

function projectVersionPage(
  value: unknown,
  expected: {
    afterVersion?: number | undefined;
    limit: number;
    tenantId: string;
    workflowId: string;
  },
): WorkflowVersionPage {
  assertBoundedProjection(value);
  const parsed = z
    .strictObject({
      items: z.array(versionRecordSchema).max(100),
      nextVersion: z
        .number()
        .int()
        .min(1)
        .max(maximumResourceVersion)
        .optional(),
    })
    .safeParse(value);
  if (!parsed.success) throw projectionMismatch();
  if (parsed.data.items.length > expected.limit) throw projectionMismatch();
  let previous = expected.afterVersion ?? Number.POSITIVE_INFINITY;
  let kind: WorkflowKind | undefined;
  const items = parsed.data.items.map((raw) => {
    const item = raw;
    const version = item.definition.version;
    if (
      item.tenantId !== expected.tenantId ||
      item.workflowId !== expected.workflowId ||
      item.definition.id !== expected.workflowId ||
      (kind !== undefined && item.definition.kind !== kind) ||
      version >= previous ||
      parseRfc3339Instant(item.publishedAt) === undefined ||
      normalizeTextProjection(item.publisherDisplayName, 200, true) !==
        item.publisherDisplayName
    ) {
      throw projectionMismatch();
    }
    if (item.publishedByMembershipId !== undefined) {
      requireProjectionUuid(item.publishedByMembershipId);
    }
    let canonical: WorkflowDesign;
    try {
      canonical = normalizeWorkflowDesign(
        item.definition.kind,
        workflowDesignOfDefinition(item.definition),
      );
      validateDesignConditionValues(canonical);
    } catch {
      throw projectionMismatch();
    }
    if (
      item.definition.initialState !==
        item.definition.states.find((state) => state.initial)?.key ||
      stableJson(workflowDesignOfDefinition(item.definition)) !==
        stableJson(canonical)
    ) {
      throw projectionMismatch();
    }
    previous = version;
    kind = item.definition.kind;
    return {
      ...item,
      definition: { ...item.definition, ...canonical },
    };
  });
  if (
    parsed.data.nextVersion !== undefined &&
    (items.length === 0 ||
      parsed.data.nextVersion !== items.at(-1)?.definition.version)
  ) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(parsed.data.nextVersion === undefined
      ? {}
      : { nextVersion: parsed.data.nextVersion }),
  };
}

function projectSimulationResult(
  value: unknown,
  workflowId: string,
  request: WorkflowSimulationRequest,
): WorkflowSimulationResult {
  assertBoundedProjection(value);
  const parsed = simulationResultSchema.safeParse(value);
  if (!parsed.success) throw projectionMismatch();
  const result = parsed.data;
  const aggregateKindFact = request.facts.find(
    (fact) => fact.field === "aggregate_kind",
  );
  if (
    result.workflowId !== workflowId ||
    (request.version !== 0 && result.version !== request.version) ||
    request.permissions.some(
      (permission) => !permission.startsWith(`${result.kind}.`),
    ) ||
    (aggregateKindFact !== undefined &&
      (aggregateKindFact.value?.type !== "text" ||
        aggregateKindFact.value.value !== result.kind))
  ) {
    throw projectionMismatch();
  }
  const requestedRoles = new Set(request.roles);
  const requestedPermissions = new Set(request.permissions);
  const requestedFields = new Set(request.providedCustomFields);
  let previous = "";
  for (const transition of result.transitions) {
    const permissionPrefix = `${result.kind}.`;
    const allGatesPass = Object.values(transition.gates).every(Boolean);
    if (
      transition.from !== request.state ||
      transition.to === transition.from ||
      transition.key <= previous ||
      transition.eligible !== allGatesPass ||
      (request.commentPresent && !transition.gates.commentSatisfied) ||
      transition.gates.roleSatisfied !==
        (transition.missingRoles.length === 0) ||
      transition.gates.permissionsSatisfied !==
        (transition.missingPermissions.length === 0) ||
      transition.gates.customFieldsSatisfied !==
        (transition.missingCustomFields.length === 0) ||
      !isCanonicalUnique(transition.missingRoles) ||
      !isCanonicalPermissions(transition.missingPermissions) ||
      !isCanonicalUnique(transition.missingCustomFields) ||
      transition.missingPermissions.some(
        (permission) => !permission.startsWith(permissionPrefix),
      ) ||
      !isCanonicalEffectPlan(transition.effects) ||
      transition.missingRoles.some((role) => requestedRoles.has(role)) ||
      transition.missingPermissions.some((permission) =>
        requestedPermissions.has(permission),
      ) ||
      transition.missingCustomFields.some((field) => requestedFields.has(field))
    ) {
      throw projectionMismatch();
    }
    previous = transition.key;
  }
  return result;
}

async function requireWorkflowEtag(
  value: string | null | undefined,
  workflowId: string,
  revision: number,
  projection: boolean,
): Promise<void> {
  const match = value ? workflowStrongEntityTagPattern.exec(value) : null;
  if (
    !match ||
    Number(match[1]) !== revision ||
    revision > maximumResourceVersion
  ) {
    if (projection) throw projectionMismatch();
    throw new WorkflowApiError("A current strong workflow ETag is required.");
  }
  const expected = await workflowStrongEtagFor(workflowId, revision);
  if (value !== expected) {
    if (projection) throw projectionMismatch();
    throw new WorkflowApiError("A current strong workflow ETag is required.");
  }
}

async function workflowStrongEtagFor(
  workflowId: string,
  revision: number,
): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new WorkflowApiError(
      "Strong workflow ETag verification is unavailable.",
    );
  }
  const digest = await subtle.digest(
    "SHA-256",
    new TextEncoder().encode(
      `periapsis.workflow-admin.etag.v1\u0000${workflowId}`,
    ),
  );
  return `"v${revision}-${base64Url(new Uint8Array(digest))}"`;
}

function base64Url(value: Uint8Array): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let result = "";
  for (let index = 0; index < value.length; index += 3) {
    const first = value[index]!;
    const second = value[index + 1];
    const third = value[index + 2];
    result += alphabet[first >> 2];
    result += alphabet[((first & 3) << 4) | ((second ?? 0) >> 4)];
    if (second !== undefined) {
      result += alphabet[((second & 15) << 2) | ((third ?? 0) >> 6)];
    }
    if (third !== undefined) result += alphabet[third & 63];
  }
  return result;
}

function normalizeTextProjection(
  value: string,
  maximumBytes: number,
  optional: boolean,
): string | undefined {
  try {
    return boundedWorkflowText(
      value,
      maximumBytes,
      "workflow response text",
      optional,
    );
  } catch {
    return undefined;
  }
}

function workflowDesignOf(workflow: ManagedWorkflow): WorkflowDesign {
  return {
    states: workflow.current.states,
    transitions: workflow.current.transitions,
  };
}

function workflowDesignOfDefinition(
  definition: WorkflowVersion["definition"],
): WorkflowDesign {
  return {
    states: definition.states,
    transitions: definition.transitions,
  };
}

function isCanonicalEffectPlan(values: WorkflowEffect[]): boolean {
  return (
    values.length >= 2 &&
    values.length <= 4 &&
    values.includes("activity") &&
    values.includes("audit") &&
    values.every(
      (value, index) =>
        effectOrder.includes(value) &&
        (index === 0 ||
          effectOrder.indexOf(values[index - 1]!) < effectOrder.indexOf(value)),
    )
  );
}

function isCanonicalUnique(values: readonly string[]): boolean {
  return values.every(
    (value, index) => index === 0 || values[index - 1]! < value,
  );
}

function isCanonicalPermissions(
  values: readonly WorkflowPermission[],
): boolean {
  return values.every(
    (value, index) =>
      index === 0 ||
      workflowPermissionOrder.indexOf(values[index - 1]!) <
        workflowPermissionOrder.indexOf(value),
  );
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }
  return `{${Object.entries(value)
    .toSorted(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
    .join(",")}}`;
}

function assertBoundedProjection(value: unknown): void {
  const budget = { nodes: 0 };
  assertBoundedProjectionNode(value, 0, budget);
}

function assertBoundedProjectionNode(
  value: unknown,
  depth: number,
  budget: { nodes: number },
): void {
  budget.nodes += 1;
  if (depth > 24 || budget.nodes > 100_000) throw projectionMismatch();
  if (Array.isArray(value)) {
    if (value.length > 500) throw projectionMismatch();
    for (const item of value) {
      assertBoundedProjectionNode(item, depth + 1, budget);
    }
    return;
  }
  if (typeof value === "string" && value.length > 4096) {
    throw projectionMismatch();
  }
  if (!isRecord(value)) return;
  const entries = Object.entries(value);
  if (entries.length > 64) throw projectionMismatch();
  for (const [key, item] of entries) {
    if (key.length > 128 || forbiddenProjectionKeys.has(key)) {
      throw projectionMismatch();
    }
    assertBoundedProjectionNode(item, depth + 1, budget);
  }
}

function requireProjectionUuid(value: string): void {
  if (!uuidV7Pattern.test(value)) throw projectionMismatch();
}

function hasForbiddenText(value: string): boolean {
  return Array.from(value).some((character) => {
    const point = character.codePointAt(0);
    return (
      point === undefined ||
      (point < 32 && point !== 9 && point !== 10) ||
      (point >= 127 && point <= 159) ||
      (point >= 0xd800 && point <= 0xdfff) ||
      point === 0x200e ||
      point === 0x200f ||
      (point >= 0x202a && point <= 0x202e) ||
      (point >= 0x2066 && point <= 0x2069)
    );
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionMismatch(): WorkflowApiError {
  return new WorkflowApiError(
    "The workflow projection was not safe to display.",
    undefined,
    "projection_mismatch",
  );
}

function toWorkflowApiError(response?: Response): WorkflowApiError {
  const status = response?.status;
  return new WorkflowApiError(fallbackForStatus(status), status);
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The workflow request was not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The server denied this workflow operation.";
    case 404:
      return "The workflow is not available in this tenant projection.";
    case 409:
      return "This attempt conflicts with current workflow state. Reload the workflow and review the latest publication before retrying.";
    case 412:
      return "This workflow changed. Reload it and review the latest revision before retrying.";
    case 428:
      return "The current workflow revision is required.";
    case 429:
      return "The workflow operation is temporarily rate limited.";
    case 503:
      return "A required workflow dependency or projection is unavailable.";
    default:
      return "The workflow request could not be completed.";
  }
}

export class WorkflowApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "WorkflowApiError";
  }
}
