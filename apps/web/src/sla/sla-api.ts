import {
  archiveTenantSlaBusinessCalendar,
  archiveTenantSlaColumn,
  archiveTenantSlaPolicy,
  createTenantSlaBusinessCalendar,
  createTenantSlaColumn,
  createTenantSlaPolicy,
  getCustomerPortalAlertSla,
  getCustomerPortalCaseSla,
  getTenantAlertSla,
  getTenantCaseSla,
  getTenantSlaBusinessCalendar,
  getTenantSlaColumn,
  getTenantSlaPolicy,
  listTenantSlaBusinessCalendars,
  listTenantSlaColumns,
  listTenantSlaPolicies,
  overrideTenantAlertSla,
  overrideTenantCaseSla,
  replaceTenantSlaBusinessCalendar,
  replaceTenantSlaColumn,
  replaceTenantSlaPolicy,
  simulateTenantSlaPolicy,
  type SlaBusinessCalendar as GeneratedBusinessCalendar,
  type SlaColumnCreateRequest as GeneratedColumnCreateRequest,
  type SlaColumn as GeneratedColumn,
  type SlaColumnReplaceRequest as GeneratedColumnReplaceRequest,
  type SlaFactPath as GeneratedFactPath,
  type SlaMetricDefinitionWrite as GeneratedMetricWrite,
  type SlaCustomerObjectProjection as GeneratedCustomerObjectProjection,
  type SlaOperatorObjectProjection as GeneratedOperatorObjectProjection,
  type SlaOverrideReceipt as GeneratedOverrideReceipt,
  type SlaPolicy as GeneratedPolicy,
  type SlaPolicyCreateRequest as GeneratedPolicyCreateRequest,
  type SlaPolicyReplaceRequest as GeneratedPolicyReplaceRequest,
  type SlaRule as GeneratedRule,
  type SlaSimulationRequest as GeneratedSimulationRequest,
  type SlaSimulationResult as GeneratedSimulationResult,
  type SlaTriggerAction as GeneratedTriggerAction,
  type SlaTriggerDefinitionWrite as GeneratedTriggerWrite,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "../lib/session-transition-transport";

import type {
  BusinessCalendar,
  BusinessCalendarWrite,
  SlaFactPath,
  SlaMatchExpression,
  SlaMetricWrite,
  SlaColumn,
  SlaColumnWrite,
  SlaCursorPage,
  SlaObjectType,
  SlaOverrideReceipt,
  SlaOverrideRequest,
  SlaPolicy,
  SlaPolicyWrite,
  SlaSimulationRequest,
  SlaSimulationResult,
  SlaTriggerAction,
  SlaTriggerWrite,
  TicketSlaProjection,
  VersionedSlaResource,
} from "./model";

export interface SlaMutationContext {
  csrfToken: string;
  idempotencyKey: string;
  tenantId: string;
}

export interface SlaVersionMutationContext extends SlaMutationContext {
  etag: string;
}

export interface SlaListContext {
  after?: string;
  includeArchived?: boolean;
  signal?: AbortSignal;
  tenantId: string;
}

export interface SlaAdminApi {
  listCalendars(
    input: SlaListContext,
  ): Promise<SlaCursorPage<BusinessCalendar>>;
  getCalendar(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedSlaResource<BusinessCalendar>>;
  createCalendar(
    input: SlaMutationContext & { body: BusinessCalendarWrite },
  ): Promise<VersionedSlaResource<BusinessCalendar>>;
  versionCalendar(
    input: SlaVersionMutationContext & {
      body: Omit<BusinessCalendarWrite, "id">;
      id: string;
    },
  ): Promise<VersionedSlaResource<BusinessCalendar>>;
  archiveCalendar(
    input: SlaVersionMutationContext & { id: string; reason: string },
  ): Promise<VersionedSlaResource<BusinessCalendar>>;

  listPolicies(input: SlaListContext): Promise<SlaCursorPage<SlaPolicy>>;
  getPolicy(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedSlaResource<SlaPolicy>>;
  createPolicy(
    input: SlaMutationContext & { body: SlaPolicyWrite },
  ): Promise<VersionedSlaResource<SlaPolicy>>;
  versionPolicy(
    input: SlaVersionMutationContext & {
      body: Omit<SlaPolicyWrite, "id">;
      id: string;
    },
  ): Promise<VersionedSlaResource<SlaPolicy>>;
  archivePolicy(
    input: SlaVersionMutationContext & { id: string; reason: string },
  ): Promise<VersionedSlaResource<SlaPolicy>>;

  listColumns(input: SlaListContext): Promise<SlaCursorPage<SlaColumn>>;
  getColumn(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedSlaResource<SlaColumn>>;
  createColumn(
    input: SlaMutationContext & { body: SlaColumnWrite },
  ): Promise<VersionedSlaResource<SlaColumn>>;
  versionColumn(
    input: SlaVersionMutationContext & {
      body: Omit<SlaColumnWrite, "id">;
      id: string;
    },
  ): Promise<VersionedSlaResource<SlaColumn>>;
  archiveColumn(
    input: SlaVersionMutationContext & { id: string; reason: string },
  ): Promise<VersionedSlaResource<SlaColumn>>;

  simulatePolicy(input: {
    body: SlaSimulationRequest;
    csrfToken: string;
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<SlaSimulationResult>;

  getTicketSla(input: {
    audience: TicketSlaProjection["audience"];
    kind: SlaObjectType;
    objectId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedSlaResource<TicketSlaProjection>>;
  overrideTicketSla(
    input: SlaMutationContext & {
      body: SlaOverrideRequest;
      etag: string;
      kind: SlaObjectType;
      objectId: string;
    },
  ): Promise<{
    projection: VersionedSlaResource<TicketSlaProjection>;
    receipt: SlaOverrideReceipt;
  }>;
}

export class SlaApiError extends Error {
  readonly code: string;
  readonly status: number | undefined;

  constructor(message: string, status?: number, code = "sla_api_error") {
    super(message);
    this.name = "SlaApiError";
    this.code = code;
    this.status = status;
  }
}

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

type GeneratedObjectProjection =
  GeneratedCustomerObjectProjection | GeneratedOperatorObjectProjection;

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestPattern = /^[0-9a-f]{64}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;

export const slaAdminApi: SlaAdminApi = {
  async listCalendars({ after, includeArchived, signal, tenantId }) {
    requireTenant(tenantId);
    return projectPage(
      unwrap(
        await listTenantSlaBusinessCalendars({
          ...requestDefaults(),
          path: { tenantId },
          query: {
            limit: 100,
            ...(after ? { after } : {}),
            ...(includeArchived === undefined ? {} : { includeArchived }),
          },
          ...(signal ? { signal } : {}),
        }),
      ),
      tenantId,
      projectCalendar,
    );
  },

  async getCalendar({ id, signal, tenantId }) {
    requireTenantAndResource(tenantId, id);
    return projectVersioned(
      await getTenantSlaBusinessCalendar({
        ...requestDefaults(),
        path: { calendarId: id, tenantId },
        ...(signal ? { signal } : {}),
      }),
      tenantId,
      id,
      projectCalendar,
      (value) => value.id,
    );
  },

  async createCalendar(input) {
    requireMutation(input);
    return projectVersioned(
      await createTenantSlaBusinessCalendar({
        ...requestDefaults(),
        body: input.body,
        headers: mutationHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      input.tenantId,
      input.body.id,
      projectCalendar,
      (value) => value.id,
    );
  },

  async versionCalendar(input) {
    requireVersionMutation(input, input.id);
    return projectVersioned(
      await replaceTenantSlaBusinessCalendar({
        ...requestDefaults(),
        body: input.body,
        headers: versionHeaders(input),
        path: { calendarId: input.id, tenantId: input.tenantId },
      }),
      input.tenantId,
      input.id,
      projectCalendar,
      (value) => value.id,
    );
  },

  async archiveCalendar(input) {
    requireArchiveMutation(input, input.id);
    const archived = await archiveTenantSlaBusinessCalendar({
      ...requestDefaults(),
      body: { reason: input.reason },
      headers: versionHeaders(input),
      path: { calendarId: input.id, tenantId: input.tenantId },
    });
    const archiveEtag = requireNoContent(archived);
    const current = await slaAdminApi.getCalendar({
      id: input.id,
      tenantId: input.tenantId,
    });
    validateArchiveFollowUp(current, archiveEtag);
    return current;
  },

  async listPolicies({ after, includeArchived, signal, tenantId }) {
    requireTenant(tenantId);
    return projectPage(
      unwrap(
        await listTenantSlaPolicies({
          ...requestDefaults(),
          path: { tenantId },
          query: {
            limit: 100,
            ...(after ? { after } : {}),
            ...(includeArchived === undefined ? {} : { includeArchived }),
          },
          ...(signal ? { signal } : {}),
        }),
      ),
      tenantId,
      projectPolicy,
    );
  },

  async getPolicy({ id, signal, tenantId }) {
    requireTenantAndResource(tenantId, id);
    return projectVersioned(
      await getTenantSlaPolicy({
        ...requestDefaults(),
        path: { policyId: id, tenantId },
        ...(signal ? { signal } : {}),
      }),
      tenantId,
      id,
      projectPolicy,
      (value) => value.id,
    );
  },

  async createPolicy(input) {
    requireMutation(input);
    return projectVersioned(
      await createTenantSlaPolicy({
        ...requestDefaults(),
        body: toGeneratedPolicyCreate(input.body),
        headers: mutationHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      input.tenantId,
      input.body.id,
      projectPolicy,
      (value) => value.id,
    );
  },

  async versionPolicy(input) {
    requireVersionMutation(input, input.id);
    return projectVersioned(
      await replaceTenantSlaPolicy({
        ...requestDefaults(),
        body: toGeneratedPolicyReplace(input.body),
        headers: versionHeaders(input),
        path: { policyId: input.id, tenantId: input.tenantId },
      }),
      input.tenantId,
      input.id,
      projectPolicy,
      (value) => value.id,
    );
  },

  async archivePolicy(input) {
    requireArchiveMutation(input, input.id);
    const archived = await archiveTenantSlaPolicy({
      ...requestDefaults(),
      body: { reason: input.reason },
      headers: versionHeaders(input),
      path: { policyId: input.id, tenantId: input.tenantId },
    });
    const archiveEtag = requireNoContent(archived);
    const current = await slaAdminApi.getPolicy({
      id: input.id,
      tenantId: input.tenantId,
    });
    validateArchiveFollowUp(current, archiveEtag);
    return current;
  },

  async listColumns({ after, includeArchived, signal, tenantId }) {
    requireTenant(tenantId);
    return projectPage(
      unwrap(
        await listTenantSlaColumns({
          ...requestDefaults(),
          path: { tenantId },
          query: {
            limit: 100,
            ...(after ? { after } : {}),
            ...(includeArchived === undefined ? {} : { includeArchived }),
          },
          ...(signal ? { signal } : {}),
        }),
      ),
      tenantId,
      projectColumn,
    );
  },

  async getColumn({ id, signal, tenantId }) {
    requireTenantAndResource(tenantId, id);
    return projectVersioned(
      await getTenantSlaColumn({
        ...requestDefaults(),
        path: { columnId: id, tenantId },
        ...(signal ? { signal } : {}),
      }),
      tenantId,
      id,
      projectColumn,
      (value) => value.id,
    );
  },

  async createColumn(input) {
    requireMutation(input);
    return projectVersioned(
      await createTenantSlaColumn({
        ...requestDefaults(),
        body: toGeneratedColumnCreate(input.body),
        headers: mutationHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      input.tenantId,
      input.body.id,
      projectColumn,
      (value) => value.id,
    );
  },

  async versionColumn(input) {
    requireVersionMutation(input, input.id);
    return projectVersioned(
      await replaceTenantSlaColumn({
        ...requestDefaults(),
        body: toGeneratedColumnReplace(input.body),
        headers: versionHeaders(input),
        path: { columnId: input.id, tenantId: input.tenantId },
      }),
      input.tenantId,
      input.id,
      projectColumn,
      (value) => value.id,
    );
  },

  async archiveColumn(input) {
    requireArchiveMutation(input, input.id);
    const archived = await archiveTenantSlaColumn({
      ...requestDefaults(),
      body: { reason: input.reason },
      headers: versionHeaders(input),
      path: { columnId: input.id, tenantId: input.tenantId },
    });
    const archiveEtag = requireNoContent(archived);
    const current = await slaAdminApi.getColumn({
      id: input.id,
      tenantId: input.tenantId,
    });
    validateArchiveFollowUp(current, archiveEtag);
    return current;
  },

  async simulatePolicy({ body, csrfToken, id, signal, tenantId }) {
    requireTenantAndResource(tenantId, id);
    requireCsrf(csrfToken);
    return projectSimulation(
      unwrap(
        await simulateTenantSlaPolicy({
          ...requestDefaults(),
          body: toGeneratedSimulation(body),
          headers: { "X-CSRF-Token": csrfToken },
          path: { policyId: id, tenantId },
          ...(signal ? { signal } : {}),
        }),
      ),
      tenantId,
      id,
    );
  },

  async getTicketSla({ audience, kind, objectId, signal, tenantId }) {
    requireTenantAndResource(tenantId, objectId);
    let result: GeneratedResult<GeneratedObjectProjection>;
    if (audience === "customer" && kind === "alert") {
      result = await getCustomerPortalAlertSla({
        ...requestDefaults(),
        path: { alertId: objectId, tenantId },
        ...(signal ? { signal } : {}),
      });
    } else if (audience === "customer" && kind === "case") {
      result = await getCustomerPortalCaseSla({
        ...requestDefaults(),
        path: { caseId: objectId, tenantId },
        ...(signal ? { signal } : {}),
      });
    } else if (audience === "operator" && kind === "alert") {
      result = await getTenantAlertSla({
        ...requestDefaults(),
        path: { alertId: objectId, tenantId },
        ...(signal ? { signal } : {}),
      });
    } else if (audience === "operator" && kind === "case") {
      result = await getTenantCaseSla({
        ...requestDefaults(),
        path: { caseId: objectId, tenantId },
        ...(signal ? { signal } : {}),
      });
    } else {
      throw new SlaApiError("A valid SLA route intent is required.");
    }
    return projectVersioned(
      result,
      tenantId,
      objectId,
      (value, expectedTenantId) =>
        projectObject(value, expectedTenantId, kind, objectId, audience),
      (value) => value.objectId,
    );
  },

  async overrideTicketSla(input) {
    requireVersionMutation(input, input.objectId);
    const result =
      input.kind === "alert"
        ? await overrideTenantAlertSla({
            ...requestDefaults(),
            body: input.body,
            headers: versionHeaders(input),
            path: { alertId: input.objectId, tenantId: input.tenantId },
          })
        : await overrideTenantCaseSla({
            ...requestDefaults(),
            body: input.body,
            headers: versionHeaders(input),
            path: { caseId: input.objectId, tenantId: input.tenantId },
          });
    const receipt = projectReceipt(
      unwrap(result),
      input.tenantId,
      input.kind,
      input.objectId,
    );
    const mutationEtag = requireEtag(result.response);
    const projection = await slaAdminApi.getTicketSla({
      audience: "operator",
      kind: input.kind,
      objectId: input.objectId,
      tenantId: input.tenantId,
    });
    if (projection.etag !== mutationEtag) throw projectionMismatch();
    return { projection, receipt };
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

function mutationHeaders(input: SlaMutationContext) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "X-CSRF-Token": input.csrfToken,
  };
}

function versionHeaders(input: SlaVersionMutationContext) {
  return { ...mutationHeaders(input), "If-Match": input.etag };
}

function toGeneratedPolicyCreate(
  input: SlaPolicyWrite,
): GeneratedPolicyCreateRequest {
  return { id: input.id, ...toGeneratedPolicyReplace(input) };
}

function toGeneratedPolicyReplace(
  input: Omit<SlaPolicyWrite, "id">,
): GeneratedPolicyReplaceRequest {
  return {
    key: input.key,
    name: input.name,
    description: input.description,
    priority: input.priority,
    objectTypes: input.objectTypes,
    matchRule: toGeneratedRule(input.matchRule),
    metrics: input.metrics.map(toGeneratedMetric),
    triggers: input.triggers.map(toGeneratedTrigger),
    effectiveFrom: input.effectiveFrom,
    ...(input.effectiveUntil === undefined
      ? {}
      : { effectiveUntil: input.effectiveUntil }),
    enabled: input.enabled,
    applyToSlaEngineSource: input.applyToSlaEngineSource,
  };
}

function toGeneratedRule(input: SlaMatchExpression): GeneratedRule {
  if (input.kind === "predicate") {
    return {
      kind: "predicate",
      predicate: {
        path: toGeneratedFactPath(input.predicate.path),
        operator: input.predicate.operator,
        values: input.predicate.values,
      },
    };
  }
  if (input.kind === "not") {
    return { kind: "not", children: [toGeneratedRule(input.children[0])] };
  }
  return {
    kind: input.kind,
    children: input.children.map(toGeneratedRule),
  };
}

function toGeneratedFactPath(input: SlaFactPath): GeneratedFactPath {
  if (input.kind === "custom_field") {
    if (!input.key)
      throw new SlaApiError("A custom-field fact key is required.");
    return { kind: "custom_field", key: input.key };
  }
  return { kind: input.kind };
}

function toGeneratedMetric(input: SlaMetricWrite): GeneratedMetricWrite {
  const common = {
    id: input.id,
    key: input.key,
    label: input.label,
    description: input.description,
    durationMicros: input.durationMicros,
    startEvent: input.startEvent,
    ...(input.pauseEvent === undefined ? {} : { pauseEvent: input.pauseEvent }),
    ...(input.resumeEvent === undefined
      ? {}
      : { resumeEvent: input.resumeEvent }),
    completionEvent: input.completionEvent,
    warning: input.warning,
    breachGraceMicros: input.breachGraceMicros,
    displayFormat: input.displayFormat,
    customerVisible: input.customerVisible,
    apiVisible: input.apiVisible,
  };
  if (input.clock === "business") {
    if (!input.calendarId || input.calendarVersion === undefined) {
      throw new SlaApiError("A business metric requires a pinned calendar.");
    }
    if (input.resetPolicy === "ignore") {
      return {
        ...common,
        clock: "business",
        calendarId: input.calendarId,
        calendarVersion: input.calendarVersion,
        resetPolicy: "ignore",
      };
    }
    if (!input.resetEvent) {
      throw new SlaApiError("A resetting metric requires a reset event.");
    }
    return {
      ...common,
      clock: "business",
      calendarId: input.calendarId,
      calendarVersion: input.calendarVersion,
      resetPolicy: input.resetPolicy,
      resetEvent: input.resetEvent,
    };
  }
  if (input.calendarId !== undefined || input.calendarVersion !== undefined) {
    throw new SlaApiError("An elapsed metric cannot bind a calendar.");
  }
  if (input.resetPolicy === "ignore") {
    return { ...common, clock: "elapsed", resetPolicy: "ignore" };
  }
  if (!input.resetEvent) {
    throw new SlaApiError("A resetting metric requires a reset event.");
  }
  return {
    ...common,
    clock: "elapsed",
    resetPolicy: input.resetPolicy,
    resetEvent: input.resetEvent,
  };
}

function toGeneratedTrigger(input: SlaTriggerWrite): GeneratedTriggerWrite {
  const common = {
    id: input.id,
    key: input.key,
    metricDefinitionId: input.metricDefinitionId,
    action: toGeneratedAction(input.action),
  };
  switch (input.kind) {
    case "consumed_percent":
      if (input.consumedPercent === undefined) throw invalidTrigger();
      return {
        ...common,
        kind: "consumed_percent",
        consumedPercent: input.consumedPercent,
      };
    case "remaining_duration":
      if (input.remainingMicros === undefined) throw invalidTrigger();
      return {
        ...common,
        kind: "remaining_duration",
        remainingMicros: input.remainingMicros,
      };
    case "due":
      return { ...common, kind: "due" };
    case "after_breach":
      if (input.offsetMicros === undefined) throw invalidTrigger();
      return {
        ...common,
        kind: "after_breach",
        offsetMicros: input.offsetMicros,
      };
    case "repeated_after_breach":
      if (
        input.offsetMicros === undefined ||
        input.repeatIntervalMicros === undefined
      )
        throw invalidTrigger();
      return {
        ...common,
        kind: "repeated_after_breach",
        offsetMicros: input.offsetMicros,
        repeatIntervalMicros: input.repeatIntervalMicros,
      };
    case "state_changed":
      if (input.targetState === undefined) throw invalidTrigger();
      return {
        ...common,
        kind: "state_changed",
        targetState: input.targetState,
      };
    case "resumed":
      return { ...common, kind: "resumed" };
    default:
      throw invalidTrigger();
  }
}

function invalidTrigger(): SlaApiError {
  return new SlaApiError("The trigger shape does not match its kind.");
}

function toGeneratedAction(input: SlaTriggerAction): GeneratedTriggerAction {
  switch (input.kind) {
    case "email":
    case "webhook":
    case "assign_operator_team":
      return { kind: input.kind, configurationId: input.configurationId };
    case "add_tag":
    case "change_priority":
    case "domain_event":
      return { kind: input.kind, value: input.value };
    case "create_task":
      return { kind: "create_task", text: input.text };
    case "create_system_alert":
      return {
        kind: "create_system_alert",
        value: input.value,
        allowRecursiveSla: input.allowRecursiveSla,
      };
    default:
      throw new SlaApiError("The trigger action kind is unsupported.");
  }
}

function toGeneratedColumnCreate(
  input: SlaColumnWrite,
): GeneratedColumnCreateRequest {
  return { id: input.id, ...toGeneratedColumnReplace(input) };
}

function toGeneratedColumnReplace(
  input: Omit<SlaColumnWrite, "id">,
): GeneratedColumnReplaceRequest {
  const common = {
    key: input.key,
    label: input.label,
    metricDefinitionId: input.metricDefinitionId,
    sortable: input.sortable,
    filterable: input.filterable,
    customerVisible: input.customerVisible,
    visibleRoleKeys: input.visibleRoleKeys,
    position: input.position,
    styleRules: input.styleRules.map((rule) => ({
      styleKey: rule.styleKey,
      ...(rule.state === undefined ? {} : { state: rule.state }),
      ...(rule.minimumPercentage === undefined
        ? {}
        : { minimumPercentage: rule.minimumPercentage }),
      ...(rule.maximumRemainingMicros === undefined
        ? {}
        : { maximumRemainingMicros: rule.maximumRemainingMicros }),
    })),
  };
  switch (input.calculation) {
    case "due_at":
    case "breached_at":
      if (input.format !== "datetime") throw invalidColumn();
      return { ...common, calculation: input.calculation, format: "datetime" };
    case "remaining_seconds":
      if (input.format !== "duration") throw invalidColumn();
      return {
        ...common,
        calculation: "remaining_seconds",
        format: "duration",
      };
    case "state":
      if (input.format !== "state_badge") throw invalidColumn();
      return { ...common, calculation: "state", format: "state_badge" };
    case "consumed_percentage":
      if (input.format !== "percentage") throw invalidColumn();
      return {
        ...common,
        calculation: "consumed_percentage",
        format: "percentage",
      };
    default:
      throw invalidColumn();
  }
}

function invalidColumn(): SlaApiError {
  return new SlaApiError("The SLA column calculation and format disagree.");
}

function toGeneratedSimulation(
  input: SlaSimulationRequest,
): GeneratedSimulationRequest {
  return {
    policyVersion: input.policyVersion,
    snapshot: {
      objectType: input.snapshot.objectType,
      evaluatedAt: input.snapshot.evaluatedAt,
      timezone: input.snapshot.timezone,
      facts: input.snapshot.facts.map((fact) => ({
        path: toGeneratedFactPath(fact.path),
        values: fact.values,
      })),
    },
    slaInstanceId: input.slaInstanceId,
    objectId: input.objectId,
    createdAt: input.createdAt,
    evaluateAt: input.evaluateAt,
    metricBindings: input.metricBindings,
    events: input.events,
  };
}

function requireMutation(input: SlaMutationContext): void {
  requireTenant(input.tenantId);
  requireCsrf(input.csrfToken);
  if (!idempotencyKeyPattern.test(input.idempotencyKey)) {
    throw new SlaApiError("A valid retry key is required.");
  }
}

function requireVersionMutation(
  input: SlaVersionMutationContext,
  resourceId: string,
): void {
  requireMutation(input);
  requireResource(resourceId);
  validateStrongEtag(input.etag);
}

function requireArchiveMutation(
  input: SlaVersionMutationContext & { reason: string },
  resourceId: string,
): void {
  requireVersionMutation(input, resourceId);
  if (
    input.reason !== input.reason.trim() ||
    input.reason.length < 8 ||
    input.reason.length > 1000
  ) {
    throw new SlaApiError("A bounded audited archive reason is required.");
  }
}

function requireCsrf(value: string): void {
  if (!value.trim() || value.length > 4096) {
    throw new SlaApiError("Request integrity context is unavailable.");
  }
}

function requireTenant(value: string): void {
  if (!uuidV7Pattern.test(value)) {
    throw new SlaApiError("A valid tenant context is required.");
  }
}

function requireResource(value: string): void {
  if (!uuidV7Pattern.test(value)) {
    throw new SlaApiError("A valid resource identifier is required.");
  }
}

function requireTenantAndResource(tenantId: string, resourceId: string): void {
  requireTenant(tenantId);
  requireResource(resourceId);
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw toSlaApiError(result.response);
}

function projectVersioned<TGenerated, TProjected>(
  result: GeneratedResult<TGenerated>,
  tenantId: string,
  expectedId: string,
  project: (value: TGenerated, tenantId: string) => TProjected,
  identity: (value: TProjected) => string,
): VersionedSlaResource<TProjected> {
  const value = project(unwrap(result), tenantId);
  if (identity(value) !== expectedId) {
    throw projectionMismatch();
  }
  return { etag: requireEtag(result.response), value };
}

function projectPage<TGenerated, TProjected>(
  value: { tenantId: string; items: TGenerated[]; nextCursor?: string },
  tenantId: string,
  project: (item: TGenerated, tenantId: string) => TProjected,
): SlaCursorPage<TProjected> {
  if (
    value.tenantId !== tenantId ||
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    (value.nextCursor !== undefined &&
      (!value.nextCursor || value.nextCursor.length > 512))
  ) {
    throw projectionMismatch();
  }
  const items = value.items.map((item) => project(item, tenantId));
  return {
    items,
    ...(value.nextCursor === undefined ? {} : { nextCursor: value.nextCursor }),
  };
}

function projectCalendar(
  value: GeneratedBusinessCalendar,
  tenantId: string,
): BusinessCalendar {
  validateCatalogResource(value, tenantId);
  if (
    !Array.isArray(value.weeklySchedules) ||
    !Array.isArray(value.exceptions)
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectPolicy(value: GeneratedPolicy, tenantId: string): SlaPolicy {
  validateCatalogResource(value, tenantId);
  if (!Array.isArray(value.metrics) || !Array.isArray(value.triggers)) {
    throw projectionMismatch();
  }
  const { effectiveUntil, ...withoutNullableUntil } = value;
  return {
    ...withoutNullableUntil,
    ...(effectiveUntil === undefined || effectiveUntil === null
      ? {}
      : { effectiveUntil }),
  };
}

function projectColumn(value: GeneratedColumn, tenantId: string): SlaColumn {
  validateCatalogResource(value, tenantId);
  return value;
}

function validateCatalogResource(
  value: {
    archivedAt?: string;
    createdAt: string;
    id: string;
    resourceVersion: number;
    revisionDigest: string;
    tenantId: string;
    updatedAt: string;
    version: number;
  },
  tenantId: string,
): void {
  if (
    value.tenantId !== tenantId ||
    !uuidV7Pattern.test(value.id) ||
    !positiveVersion(value.version) ||
    !positiveVersion(value.resourceVersion) ||
    !digestPattern.test(value.revisionDigest) ||
    !rfc3339(value.createdAt) ||
    !rfc3339(value.updatedAt) ||
    (value.archivedAt !== undefined && !rfc3339(value.archivedAt))
  ) {
    throw projectionMismatch();
  }
}

function projectSimulation(
  value: GeneratedSimulationResult,
  tenantId: string,
  policyId: string,
): SlaSimulationResult {
  if (
    value.tenantId !== tenantId ||
    value.policyId !== policyId ||
    !positiveVersion(value.policyVersion) ||
    !digestPattern.test(value.simulationDigest) ||
    !Array.isArray(value.metrics) ||
    value.metrics.length > 32
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectObject(
  value: GeneratedObjectProjection,
  tenantId: string,
  objectType: SlaObjectType,
  objectId: string,
  audience: TicketSlaProjection["audience"],
): TicketSlaProjection {
  const allowed =
    value.audience === "operator"
      ? new Set([
          "audience",
          "tenantId",
          "objectType",
          "objectId",
          "slaInstanceId",
          "aggregateVersion",
          "policyId",
          "policyVersion",
          "projectedAt",
          "metrics",
          "columns",
        ])
      : new Set([
          "audience",
          "tenantId",
          "objectType",
          "objectId",
          "projectedAt",
          "metrics",
          "columns",
        ]);
  if (
    value.tenantId !== tenantId ||
    value.audience !== audience ||
    value.objectType !== objectType ||
    value.objectId !== objectId ||
    !rfc3339(value.projectedAt) ||
    !exactKeys(value, allowed)
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectReceipt(
  value: GeneratedOverrideReceipt,
  tenantId: string,
  objectType: SlaObjectType,
  objectId: string,
): SlaOverrideReceipt {
  if (
    value.tenantId !== tenantId ||
    value.objectType !== objectType ||
    value.objectId !== objectId ||
    !uuidV7Pattern.test(value.overrideId) ||
    !rfc3339(value.occurredAt)
  ) {
    throw projectionMismatch();
  }
  return value;
}

function requireNoContent(result: GeneratedResult<void>): string {
  if (result.error !== undefined || result.response?.status !== 204) {
    throw toSlaApiError(result.response);
  }
  return requireEtag(result.response);
}

function requireEtag(response: Response | undefined): string {
  const etag = response?.headers.get("ETag");
  if (!etag) throw projectionMismatch();
  validateStrongEtag(etag);
  return etag;
}

function validateArchiveFollowUp<T extends { archivedAt?: string }>(
  current: VersionedSlaResource<T>,
  archiveEtag: string,
): void {
  if (
    current.etag !== archiveEtag ||
    current.value.archivedAt === undefined ||
    !rfc3339(current.value.archivedAt)
  ) {
    throw projectionMismatch();
  }
}

function validateStrongEtag(value: string): void {
  if (
    value.length < 3 ||
    value.length > 194 ||
    value.startsWith("W/") ||
    value[0] !== '"' ||
    value.at(-1) !== '"' ||
    value.slice(1, -1).includes('"') ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0);
      return point === undefined || point < 33 || point === 127;
    })
  ) {
    throw new SlaApiError("A current strong entity tag is required.");
  }
}

function exactKeys(value: object, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function positiveVersion(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1;
}

function rfc3339(value: string): boolean {
  return (
    /(?:Z|[+-]\d{2}:\d{2})$/u.test(value) && Number.isFinite(Date.parse(value))
  );
}

function projectionMismatch(): SlaApiError {
  return new SlaApiError(
    "The SLA API returned an inconsistent or cross-tenant projection.",
    undefined,
    "projection_mismatch",
  );
}

function toSlaApiError(response: Response | undefined): SlaApiError {
  const status = response?.status;
  const message =
    status === 401
      ? "Your session is no longer valid."
      : status === 403
        ? "Current authority does not permit this SLA operation."
        : status === 404
          ? "The SLA resource is unavailable in this tenant."
          : status === 409
            ? "The SLA operation conflicts with current state or retry history."
            : status === 412 || status === 428
              ? "The SLA resource changed; refresh before retrying."
              : status === 503
                ? "The SLA service is temporarily unavailable."
                : "The SLA operation could not be completed.";
  return new SlaApiError(message, status);
}
