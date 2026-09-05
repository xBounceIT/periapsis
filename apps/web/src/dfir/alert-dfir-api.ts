import {
  linkTenantAlertDfirIndicator,
  linkTenantAlertDfirAsset,
  unlinkTenantAlertDfirIndicator,
  unlinkTenantAlertDfirAsset,
  appendTenantAlertDfirCustodyEvent,
  assignTenantAlertDfirTask,
  collectTenantAlertDfirEvidence,
  createTenantAlertDfirAsset,
  createTenantAlertDfirIndicator,
  createTenantAlertDfirRelationship,
  createTenantAlertDfirTask,
  createTenantAlertDfirTimelineEvent,
  getTenantAlertDfirWorkspace,
  prepareTenantAlertDfirAttachmentDownload,
  prepareTenantAlertDfirAttachmentUpload,
  replaceTenantAlertDfirTaskDetails,
  replaceTenantAlertDfirTaskChecklist,
  replaceTenantAlertDfirTaskComments,
  replaceTenantAlertDfirAsset,
  replaceTenantAlertDfirIndicator,
  rescheduleTenantAlertDfirTask,
  retractTenantAlertDfirRelationship,
  transitionTenantAlertDfirTask,
  type DfirAlertAsset,
  type DfirAlertCustodyAppendRequest,
  type DfirAlertEvidence,
  type DfirAlertEvidenceCollectRequest,
  type DfirAlertIndicator,
  type DfirAlertRelationship,
  type DfirAlertRelationshipCreateRequest,
  type DfirAlertRelationshipRetractRequest,
  type DfirAlertTask,
  type DfirAlertTaskAssignmentRequest,
  type DfirAlertTaskChecklistRequest,
  type DfirAlertTaskCreateRequest,
  type DfirAlertTaskDueDateRequest,
  type DfirAlertTaskTransitionRequest,
  type DfirAlertTimelineEvent,
  type DfirAlertTimelineEventCreateRequest,
  type DfirAlertWorkspace,
  type DfirAssetCreateRequest,
  type DfirAssetReplaceRequest,
  type DfirAttachment,
  type DfirAttachmentDownloadRequest,
  type DfirAttachmentUploadRequest,
  type DfirEntityReference,
  type DfirIndicatorCreateRequest,
  type DfirIndicatorReplaceRequest,
  type DfirPreparedDownload,
  type DfirPreparedUpload,
  type DfirTaskDetailsRequest,
  type DfirTaskCommentsRequest,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  maximumDfirCustodyEvents,
  validEvidenceCustody,
} from "./evidence-custody";
import { strongVersionEtag } from "./case-dfir-api";
import type { DfirAlertData } from "./model";
import { browserUploadHeaders } from "./upload-request";
import { relatedRootsFor, sanitizeSharedResources } from "./shared-resources";

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const digestPattern = /^[0-9a-f]{64}$/u;
const stableKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const tagPattern = /^[a-z][a-z0-9_.:-]{0,63}$/u;
const maximumDfirResourceVersion = Number.MAX_SAFE_INTEGER;
const indicatorTypes = [
  "ipv4",
  "ipv6",
  "domain",
  "hostname",
  "url",
  "email",
  "md5",
  "sha1",
  "sha256",
  "sha512",
  "filename",
  "registry_key",
  "process",
  "mutex",
  "cve",
  "custom",
] as const;
const tlpValues = ["red", "amber", "green", "clear"] as const;
const maliciousValues = [
  "unknown",
  "benign",
  "suspicious",
  "confirmed",
] as const;
const criticalityValues = ["low", "medium", "high", "critical"] as const;
const taskStatuses = [
  "todo",
  "in_progress",
  "blocked",
  "done",
  "cancelled",
] as const;
const taskPriorities = ["low", "medium", "high", "urgent"] as const;
const evidenceClassifications = [
  "public",
  "internal",
  "confidential",
  "restricted",
] as const;
const temporalPrecisions = [
  "year",
  "month",
  "day",
  "hour",
  "minute",
  "second",
  "millisecond",
  "microsecond",
] as const;
const visibilityValues = ["public", "private"] as const;
const scanStates = [
  "pending_upload",
  "uploaded",
  "verifying",
  "quarantined",
  "scanning",
  "available",
  "rejected",
  "scan_failed",
  "retained",
  "deleted",
] as const;
const custodyActions = [
  "collected",
  "accessed",
  "transferred",
  "sealed",
  "unsealed",
  "scan_state_changed",
  "retention_changed",
  "legal_hold_placed",
  "legal_hold_released",
  "destroyed",
] as const;

export interface AlertDfirWorkspaceSnapshot {
  data: DfirAlertData;
  workspace: DfirAlertWorkspace;
}

export type AlertDfirCreateOperation =
  | { body: DfirIndicatorCreateRequest; panel: "iocs" }
  | { body: DfirAssetCreateRequest; panel: "assets" }
  | { body: DfirAlertEvidenceCollectRequest; panel: "evidence" }
  | { body: DfirAlertTimelineEventCreateRequest; panel: "timeline" }
  | { body: DfirAlertTaskCreateRequest; panel: "tasks" }
  | { body: DfirAlertRelationshipCreateRequest; panel: "relationships" };

export type AlertDfirReplaceOperation =
  | {
      body: DfirIndicatorReplaceRequest;
      panel: "iocs";
      resourceId: string;
    }
  | {
      body: DfirAssetReplaceRequest;
      panel: "assets";
      resourceId: string;
    };

interface MutationContext {
  alertId: string;
  csrfToken: string;
  idempotencyKey: string;
  signal?: AbortSignal;
  tenantId: string;
}

export interface AlertDfirApi {
  changeLink(
    input: MutationContext & {
      eventId: string;
      expectedVersion: number;
      linked: boolean;
      resourceId: string;
      resourceKind: "ioc" | "asset";
    },
  ): Promise<void>;
  getWorkspace(input: {
    alertId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<AlertDfirWorkspaceSnapshot>;
  create(
    input: MutationContext & { operation: AlertDfirCreateOperation },
  ): Promise<void>;
  replace(
    input: MutationContext & { operation: AlertDfirReplaceOperation },
  ): Promise<void>;
  appendCustody(
    input: MutationContext & {
      body: DfirAlertCustodyAppendRequest;
      evidenceId: string;
    },
  ): Promise<void>;
  transitionTask(
    input: MutationContext & {
      body: DfirAlertTaskTransitionRequest;
      taskId: string;
    },
  ): Promise<void>;
  replaceTaskDetails(
    input: MutationContext & {
      body: DfirTaskDetailsRequest;
      taskId: string;
    },
  ): Promise<void>;
  assignTask(
    input: MutationContext & {
      body: DfirAlertTaskAssignmentRequest;
      taskId: string;
    },
  ): Promise<void>;
  rescheduleTask(
    input: MutationContext & {
      body: DfirAlertTaskDueDateRequest;
      taskId: string;
    },
  ): Promise<void>;
  replaceTaskChecklist(
    input: MutationContext & {
      body: DfirAlertTaskChecklistRequest;
      taskId: string;
    },
  ): Promise<void>;
  replaceTaskComments(
    input: MutationContext & {
      body: DfirTaskCommentsRequest;
      taskId: string;
    },
  ): Promise<void>;
  retractRelationship(
    input: MutationContext & {
      body: DfirAlertRelationshipRetractRequest;
      relationshipId: string;
    },
  ): Promise<void>;
  prepareUpload(
    input: MutationContext & { body: DfirAttachmentUploadRequest },
  ): Promise<DfirPreparedUpload>;
  upload(input: {
    file: File;
    prepared: DfirPreparedUpload;
    signal?: AbortSignal;
  }): Promise<void>;
  prepareDownload(input: {
    alertId: string;
    attachmentId: string;
    body: DfirAttachmentDownloadRequest;
    csrfToken: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<DfirPreparedDownload>;
}

export class AlertDfirApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "AlertDfirApiError";
    this.status = status;
  }
}

export const alertDfirApi: AlertDfirApi = {
  async getWorkspace({ alertId, signal, tenantId }) {
    requireCoordinates(tenantId, alertId);
    const result = await getTenantAlertDfirWorkspace({
      ...requestDefaults(),
      path: { alertId, tenantId },
      ...(signal ? { signal } : {}),
    });
    return projectAlertWorkspace(unwrap(result, 200), tenantId, alertId);
  },

  async create(input) {
    requireMutation(input);
    const common = {
      ...requestDefaults(),
      headers: mutationHeaders(input),
      path: { alertId: input.alertId, tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    switch (input.operation.panel) {
      case "iocs": {
        const result = await createTenantAlertDfirIndicator({
          ...common,
          body: input.operation.body,
        });
        validateVersionedResponse(
          unwrap(result, 201),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.indicatorId,
        );
        return;
      }
      case "assets": {
        const result = await createTenantAlertDfirAsset({
          ...common,
          body: input.operation.body,
        });
        validateVersionedResponse(
          unwrap(result, 201),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.assetId,
        );
        return;
      }
      case "evidence": {
        const result = await collectTenantAlertDfirEvidence({
          ...common,
          body: input.operation.body,
        });
        validateVersionedResponse(
          sanitizeEvidence(unwrap(result, 201), input.tenantId, input.alertId),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.evidenceId,
          true,
        );
        return;
      }
      case "timeline": {
        const result = await createTenantAlertDfirTimelineEvent({
          ...common,
          body: input.operation.body,
        });
        validateVersionedResponse(
          unwrap(result, 201),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.timelineEventId,
        );
        return;
      }
      case "tasks": {
        const result = await createTenantAlertDfirTask({
          ...common,
          body: input.operation.body,
        });
        validateVersionedResponse(
          unwrap(result, 201),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.taskId,
          true,
        );
        return;
      }
      case "relationships": {
        const result = await createTenantAlertDfirRelationship({
          ...common,
          body: input.operation.body,
        });
        validateRelationshipResponse(
          unwrap(result, 201),
          result.response,
          input.tenantId,
          input.alertId,
          input.operation.body.relationshipId,
        );
        return;
      }
    }
  },

  async changeLink(input) {
    requireMutation(input);
    requireCoordinates(input.resourceId, input.eventId);
    const common = {
      ...requestDefaults(),
      headers: versionHeaders(input, input.expectedVersion),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    if (input.resourceKind === "ioc" && input.linked) {
      const result = await linkTenantAlertDfirIndicator({
        ...common,
        body: { linkId: input.eventId, expectedVersion: input.expectedVersion },
        path: {
          tenantId: input.tenantId,
          alertId: input.alertId,
          indicatorId: input.resourceId,
        },
      });
      validateVersionedResponse(
        unwrap(result, 200),
        result.response,
        input.tenantId,
        input.alertId,
        input.resourceId,
      );
      if (result.data?.version !== input.expectedVersion + 1)
        throw projectionMismatch();
      return;
    }
    if (input.resourceKind === "ioc" && !input.linked) {
      const result = await unlinkTenantAlertDfirIndicator({
        ...common,
        body: {
          unlinkId: input.eventId,
          expectedVersion: input.expectedVersion,
        },
        path: {
          tenantId: input.tenantId,
          alertId: input.alertId,
          indicatorId: input.resourceId,
        },
      });
      validateVersionedResponse(
        unwrap(result, 200),
        result.response,
        input.tenantId,
        input.alertId,
        input.resourceId,
      );
      if (result.data?.version !== input.expectedVersion + 1)
        throw projectionMismatch();
      return;
    }
    if (input.resourceKind === "asset" && input.linked) {
      const result = await linkTenantAlertDfirAsset({
        ...common,
        body: { linkId: input.eventId, expectedVersion: input.expectedVersion },
        path: {
          tenantId: input.tenantId,
          alertId: input.alertId,
          assetId: input.resourceId,
        },
      });
      validateVersionedResponse(
        unwrap(result, 200),
        result.response,
        input.tenantId,
        input.alertId,
        input.resourceId,
      );
      if (result.data?.version !== input.expectedVersion + 1)
        throw projectionMismatch();
      return;
    }
    if (input.resourceKind === "asset" && !input.linked) {
      const result = await unlinkTenantAlertDfirAsset({
        ...common,
        body: {
          unlinkId: input.eventId,
          expectedVersion: input.expectedVersion,
        },
        path: {
          tenantId: input.tenantId,
          alertId: input.alertId,
          assetId: input.resourceId,
        },
      });
      validateVersionedResponse(
        unwrap(result, 200),
        result.response,
        input.tenantId,
        input.alertId,
        input.resourceId,
      );
      if (result.data?.version !== input.expectedVersion + 1)
        throw projectionMismatch();
      return;
    }
    throw projectionMismatch();
  },

  async replace(input) {
    requireMutation(input);
    requireCoordinates(input.operation.resourceId);
    const expectedVersion = input.operation.body.expectedVersion;
    const common = {
      ...requestDefaults(),
      headers: versionHeaders(input, expectedVersion),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    if (input.operation.panel === "iocs") {
      const result = await replaceTenantAlertDfirIndicator({
        ...common,
        body: input.operation.body,
        path: {
          alertId: input.alertId,
          indicatorId: input.operation.resourceId,
          tenantId: input.tenantId,
        },
      });
      validateVersionedResponse(
        unwrap(result, 200),
        result.response,
        input.tenantId,
        input.alertId,
        input.operation.resourceId,
      );
      if (result.data?.version !== expectedVersion + 1)
        throw projectionMismatch();
      return;
    }
    const result = await replaceTenantAlertDfirAsset({
      ...common,
      body: input.operation.body,
      path: {
        alertId: input.alertId,
        assetId: input.operation.resourceId,
        tenantId: input.tenantId,
      },
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.operation.resourceId,
    );
    if (result.data?.version !== expectedVersion + 1)
      throw projectionMismatch();
  },

  async appendCustody(input) {
    requireMutation(input);
    requireCoordinates(input.evidenceId);
    requireInteger(input.body.expectedVersion, 1, maximumDfirCustodyEvents - 1);
    const expectedVersion = input.body.expectedVersion;
    const result = await appendTenantAlertDfirCustodyEvent({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        evidenceId: input.evidenceId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      sanitizeEvidence(unwrap(result, 200), input.tenantId, input.alertId),
      result.response,
      input.tenantId,
      input.alertId,
      input.evidenceId,
      true,
      expectedVersion,
    );
  },

  async transitionTask(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await transitionTenantAlertDfirTask({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async replaceTaskDetails(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await replaceTenantAlertDfirTaskDetails({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async assignTask(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await assignTenantAlertDfirTask({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async rescheduleTask(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await rescheduleTenantAlertDfirTask({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async replaceTaskChecklist(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await replaceTenantAlertDfirTaskChecklist({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async replaceTaskComments(input) {
    requireMutation(input);
    requireCoordinates(input.taskId);
    const expectedVersion = input.body.expectedVersion;
    const result = await replaceTenantAlertDfirTaskComments({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        taskId: input.taskId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateVersionedResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.taskId,
      true,
      expectedVersion,
    );
  },

  async retractRelationship(input) {
    requireMutation(input);
    requireCoordinates(input.relationshipId);
    const expectedVersion = input.body.expectedVersion;
    const result = await retractTenantAlertDfirRelationship({
      ...requestDefaults(),
      body: input.body,
      headers: versionHeaders(input, expectedVersion),
      path: {
        alertId: input.alertId,
        relationshipId: input.relationshipId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    validateRelationshipResponse(
      unwrap(result, 200),
      result.response,
      input.tenantId,
      input.alertId,
      input.relationshipId,
      expectedVersion,
    );
  },

  async prepareUpload(input) {
    requireMutation(input);
    requireAlertSubject(input.body.subject, input.alertId);
    const result = await prepareTenantAlertDfirAttachmentUpload({
      ...requestDefaults(),
      body: input.body,
      headers: mutationHeaders(input),
      path: { alertId: input.alertId, tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return sanitizePreparedUpload(
      unwrap(result, 201),
      input.tenantId,
      input.body,
    );
  },

  async upload({ file, prepared, signal }) {
    validateCapabilityUrl(prepared.uploadUrl, prepared.expiresAt);
    const response = await globalThis.fetch(prepared.uploadUrl, {
      body: file,
      cache: "no-store",
      credentials: "omit",
      headers: browserUploadHeaders(prepared, file),
      method: "PUT",
      redirect: "error",
      referrerPolicy: "no-referrer",
      ...(signal ? { signal } : {}),
    });
    if (!response.ok) {
      throw new AlertDfirApiError(
        "The protected file upload could not be completed.",
        response.status,
      );
    }
  },

  async prepareDownload(input) {
    requireCoordinates(input.tenantId, input.alertId, input.attachmentId);
    requireCsrf(input.csrfToken);
    requireAlertSubject(input.body.subject, input.alertId);
    const result = await prepareTenantAlertDfirAttachmentDownload({
      ...requestDefaults(),
      body: input.body,
      headers: { "X-CSRF-Token": input.csrfToken },
      path: {
        alertId: input.alertId,
        attachmentId: input.attachmentId,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    return sanitizePreparedDownload(
      unwrap(result, 200),
      input.tenantId,
      input.attachmentId,
      input.body,
    );
  },
};

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    cache: "no-store" as const,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function mutationHeaders(
  input: Pick<MutationContext, "csrfToken" | "idempotencyKey">,
) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "X-CSRF-Token": input.csrfToken,
  };
}

function versionHeaders(
  input: Pick<MutationContext, "csrfToken" | "idempotencyKey">,
  version: number,
) {
  if (!validVersion(version) || version >= maximumDfirResourceVersion) {
    throw projectionMismatch();
  }
  return { ...mutationHeaders(input), "If-Match": strongVersionEtag(version) };
}

function requireMutation(input: MutationContext): void {
  requireCoordinates(input.tenantId, input.alertId);
  requireCsrf(input.csrfToken);
  if (!idempotencyKeyPattern.test(input.idempotencyKey)) {
    throw new AlertDfirApiError("A valid retry key is required.");
  }
}

function requireCsrf(value: string): void {
  if (!value || value.trim() !== value || value.length > 4_096) {
    throw new AlertDfirApiError("Request integrity context is unavailable.");
  }
}

function requireCoordinates(...values: string[]): void {
  if (values.length === 0 || values.some((value) => !validUuid(value))) {
    throw new AlertDfirApiError(
      "Canonical Alert DFIR coordinates are required.",
    );
  }
}

function unwrap<T>(result: GeneratedResult<T>, expectedStatus: number): T {
  if (
    result.data === undefined ||
    result.error !== undefined ||
    result.response?.status !== expectedStatus
  ) {
    throw toApiError(result.response);
  }
  if (result.response.headers.get("Cache-Control") !== "no-store") {
    throw projectionMismatch();
  }
  return result.data;
}

export function projectAlertWorkspace(
  value: DfirAlertWorkspace,
  tenantId: string,
  alertId: string,
): AlertDfirWorkspaceSnapshot {
  if (
    value.tenantId !== tenantId ||
    value.alertId !== alertId ||
    !boundedArray(value.indicators, 500) ||
    !boundedArray(value.assets, 500) ||
    !boundedArray(value.evidence, 500) ||
    !boundedArray(value.timeline, 1_000) ||
    !boundedArray(value.tasks, 500) ||
    !boundedArray(value.attachments, 500) ||
    !boundedArray(value.relationships, 1_000)
  ) {
    throw projectionMismatch();
  }
  try {
    const indicators = value.indicators.map((item) =>
      sanitizeIndicator(item, tenantId, alertId),
    );
    const assets = value.assets.map((item) =>
      sanitizeAsset(item, tenantId, alertId),
    );
    const evidence = value.evidence.map((item) =>
      sanitizeEvidence(item, tenantId, alertId),
    );
    const tasks = value.tasks.map((item) =>
      sanitizeTask(item, tenantId, alertId),
    );
    const relationships = value.relationships.map((item) =>
      sanitizeRelationship(item, tenantId, alertId),
    );
    const indicatorIds = new Set(indicators.map(({ id }) => id));
    const assetIds = new Set(assets.map(({ id }) => id));
    const evidenceIds = new Set(evidence.map(({ id }) => id));
    const taskIds = new Set(tasks.map(({ id }) => id));
    const workspace: DfirAlertWorkspace = {
      sharedResources: sanitizeSharedResources(
        value.sharedResources,
        indicators,
        assets,
        { kind: "alert", id: alertId },
      ),
      alertId,
      assets,
      attachments: value.attachments.map((item) => {
        const attachment = sanitizeAttachment(item, tenantId, item.id);
        if (
          !isWorkspaceSubject(
            attachment.subject,
            alertId,
            indicatorIds,
            assetIds,
            evidenceIds,
            taskIds,
          )
        ) {
          throw projectionMismatch();
        }
        return attachment;
      }),
      evidence,
      indicators,
      relationships,
      tasks,
      tenantId,
      timeline: value.timeline.map((item) => {
        const event = sanitizeTimeline(item, tenantId, alertId);
        if (
          event.event.iocIds.some((id) => !indicatorIds.has(id)) ||
          event.event.assetIds.some((id) => !assetIds.has(id)) ||
          event.event.evidenceIds.some((id) => !evidenceIds.has(id))
        ) {
          throw projectionMismatch();
        }
        return event;
      }),
    };
    if (
      !uniqueResourceIds(workspace.indicators) ||
      !uniqueResourceIds(workspace.assets) ||
      !uniqueResourceIds(workspace.evidence) ||
      !uniqueResourceIds(workspace.timeline) ||
      !uniqueResourceIds(workspace.tasks) ||
      !uniqueResourceIds(workspace.attachments) ||
      !uniqueResourceIds(workspace.relationships)
    ) {
      throw projectionMismatch();
    }
    return {
      workspace,
      data: {
        assets: workspace.assets.map((item) => ({
          relatedRoots: relatedRootsFor(
            workspace.sharedResources,
            "asset",
            item.id,
          ),
          addresses: [...item.asset.ipAddresses, ...item.asset.macAddresses],
          assetType: item.asset.assetType,
          criticality: item.asset.criticality,
          environment: item.asset.environment,
          ...(item.asset.fqdn ? { fqdn: item.asset.fqdn } : {}),
          ...(item.asset.hostname ? { hostname: item.asset.hostname } : {}),
          id: item.id,
        })),
        evidence: workspace.evidence.map((item) => ({
          classification: item.classification,
          custody: item.custody.map((event) => ({
            action: event.action,
            actorLabel: compactIdentity(event.actorId),
            id: event.id,
            occurredAt: event.occurredAt,
            sequence: event.sequence,
          })),
          evidenceType: item.evidenceType,
          id: item.id,
          legalHold: item.legalHold,
          scanState: item.scanState,
          sha256: item.contentSha256,
          sizeBytes: item.sizeBytes,
          title: item.title,
        })),
        attachments: workspace.attachments.map((item) => ({
          filename: item.originalFilename,
          id: item.id,
          scanState: item.scanState,
          uploadedAt: item.uploadedAt,
          visibility: item.visibility,
        })),
        iocs: workspace.indicators.map((item) => ({
          relatedRoots: relatedRootsFor(
            workspace.sharedResources,
            "ioc",
            item.id,
          ),
          confidence: item.indicator.confidence,
          id: item.id,
          malicious: item.indicator.malicious,
          tags: [...item.indicator.tags],
          tlp: item.indicator.tlp,
          type: item.indicator.type,
          value: item.indicator.value,
        })),
        relationships: workspace.relationships.map((item) => ({
          id: item.id,
          relationshipType: item.relationshipType,
          sourceLabel: referenceLabel(item.source),
          targetLabel: referenceLabel(item.target),
        })),
        tasks: workspace.tasks.map((item) => ({
          ...(item.assigneeId
            ? { assigneeLabel: compactIdentity(item.assigneeId) }
            : {}),
          checklistCompleted: item.checklist.filter((check) => check.completed)
            .length,
          checklistTotal: item.checklist.length,
          ...(item.dueAt ? { dueAt: item.dueAt } : {}),
          id: item.id,
          priority: item.priority,
          status: item.status,
          title: item.title,
          version: item.version,
        })),
        timeline: workspace.timeline.map((item) => ({
          category: item.event.category,
          ...(item.event.description
            ? { description: item.event.description }
            : {}),
          eventTime: item.event.eventTime,
          id: item.id,
          precision: item.event.precision,
          source: item.event.source,
          title: item.event.title,
        })),
      },
    };
  } catch {
    throw projectionMismatch();
  }
}

function sanitizeIndicator(
  value: DfirAlertIndicator,
  tenantId: string,
  alertId: string,
): DfirAlertIndicator {
  validateAlertResource(value, tenantId, alertId, value.id);
  const indicator = value.indicator;
  requireStringArray(indicator.tags, 256, false, 64, tagPattern);
  return {
    alertId,
    id: value.id,
    indicator: {
      confidence: requireInteger(indicator.confidence, 0, 100),
      description: requireString(indicator.description, 0, 16_384),
      ...(indicator.enrichment === undefined
        ? {}
        : { enrichment: sanitizeDocument(indicator.enrichment) }),
      firstSeen: requireInstant(indicator.firstSeen),
      lastSeen: requireInstant(indicator.lastSeen),
      malicious: requireOneOf(indicator.malicious, maliciousValues),
      source: requireString(indicator.source, 1, 512),
      tags: [...indicator.tags],
      tlp: requireOneOf(indicator.tlp, tlpValues),
      type: requireOneOf(indicator.type, indicatorTypes),
      value: requireString(indicator.value, 1, 8_192),
    },
    tenantId,
    version: value.version,
  };
}

function sanitizeAsset(
  value: DfirAlertAsset,
  tenantId: string,
  alertId: string,
): DfirAlertAsset {
  validateAlertResource(value, tenantId, alertId, value.id);
  const asset = value.asset;
  requireStringArray(asset.ipAddresses, 256, false, 45);
  requireStringArray(asset.macAddresses, 256, false, 64);
  requireStringArray(asset.tags, 256, false, 64, tagPattern);
  return {
    alertId,
    asset: {
      assetType: requireString(asset.assetType, 1, 64, stableKeyPattern),
      businessUnit: requireString(asset.businessUnit, 0, 512),
      criticality: requireOneOf(asset.criticality, criticalityValues),
      ...(asset.customAttributes === undefined
        ? {}
        : { customAttributes: sanitizeDocument(asset.customAttributes) }),
      environment: requireString(asset.environment, 1, 64, stableKeyPattern),
      externalId: requireString(asset.externalId, 0, 512),
      firstSeen: requireInstant(asset.firstSeen),
      fqdn: requireString(asset.fqdn, 0, 253),
      hostname: requireString(asset.hostname, 0, 253),
      ipAddresses: [...asset.ipAddresses],
      lastSeen: requireInstant(asset.lastSeen),
      macAddresses: [...asset.macAddresses],
      operatingSystem: requireString(asset.operatingSystem, 0, 512),
      owner: requireString(asset.owner, 0, 512),
      tags: [...asset.tags],
    },
    id: value.id,
    tenantId,
    version: value.version,
  };
}

function sanitizeEvidence(
  value: DfirAlertEvidence,
  tenantId: string,
  alertId: string,
): DfirAlertEvidence {
  validateAlertResource(value, tenantId, alertId, value.id);
  if (
    !boundedArray(value.custody, maximumDfirCustodyEvents) ||
    !digestPattern.test(value.contentSha256)
  ) {
    throw projectionMismatch();
  }
  const custody = value.custody.map((event) => ({
    action: requireOneOf(event.action, custodyActions),
    actorId: requireUuid(event.actorId),
    eventHash: requireDigest(event.eventHash),
    id: requireUuid(event.id),
    occurredAt: requireInstant(event.occurredAt),
    previousHash: requireDigest(event.previousHash),
    reason: requireString(event.reason, 1, 2_000),
    sequence: requireInteger(event.sequence, 1, maximumDfirCustodyEvents),
    stateValue: requireString(event.stateValue, 0, 512),
  }));
  if (!validEvidenceCustody(value.version, custody)) {
    throw projectionMismatch();
  }
  return {
    alertId,
    classification: requireOneOf(value.classification, evidenceClassifications),
    collectedAt: requireInstant(value.collectedAt),
    collectedBy: requireUuid(value.collectedBy),
    contentSha256: value.contentSha256,
    custody,
    description: requireString(value.description, 0, 16_384),
    destroyed: requireBoolean(value.destroyed),
    detectedMime: requireString(value.detectedMime, 3, 512),
    evidenceType: requireString(value.evidenceType, 1, 64, stableKeyPattern),
    id: value.id,
    legalHold: requireBoolean(value.legalHold),
    ...(value.retentionUntil === undefined
      ? {}
      : { retentionUntil: requireInstant(value.retentionUntil) }),
    scanState: requireOneOf(value.scanState, scanStates),
    sealed: requireBoolean(value.sealed),
    sizeBytes: requireInteger(value.sizeBytes, 1, 5_000_000_000),
    source: requireString(value.source, 1, 512),
    storageObjectId: requireUuid(value.storageObjectId),
    tenantId,
    title: requireString(value.title, 1, 512),
    version: value.version,
  };
}

function sanitizeTimeline(
  value: DfirAlertTimelineEvent,
  tenantId: string,
  alertId: string,
): DfirAlertTimelineEvent {
  validateAlertResource(value, tenantId, alertId, value.id);
  const event = value.event;
  requireStringArray(event.iocIds, 256, true);
  requireStringArray(event.assetIds, 256, true);
  requireStringArray(event.evidenceIds, 256, true);
  requireStringArray(event.tags, 256, false, 64, tagPattern);
  return {
    alertId,
    event: {
      ...(event.actorId === undefined
        ? {}
        : { actorId: requireUuid(event.actorId) }),
      assetIds: [...event.assetIds],
      category: requireString(event.category, 1, 64, stableKeyPattern),
      description: requireString(event.description, 0, 16_384),
      eventTime: requireInstant(event.eventTime),
      evidenceIds: [...event.evidenceIds],
      iocIds: [...event.iocIds],
      originalTimezone: requireString(event.originalTimezone, 1, 128),
      precision: requireOneOf(event.precision, temporalPrecisions),
      source: requireString(event.source, 1, 512),
      tags: [...event.tags],
      title: requireString(event.title, 1, 512),
    },
    id: value.id,
    ingestedAt: requireInstant(value.ingestedAt),
    tenantId,
    version: value.version,
  };
}

function sanitizeTask(
  value: DfirAlertTask,
  tenantId: string,
  alertId: string,
): DfirAlertTask {
  validateAlertResource(value, tenantId, alertId, value.id);
  if (!boundedArray(value.checklist, 100)) throw projectionMismatch();
  requireStringArray(value.commentIds, 1_000, true);
  const checklist = value.checklist.map((item) => {
    const completed = requireBoolean(item.completed);
    if (
      completed !==
      (item.completedAt !== undefined && item.completedBy !== undefined)
    ) {
      throw projectionMismatch();
    }
    return {
      completed,
      ...(item.completedAt === undefined
        ? {}
        : { completedAt: requireInstant(item.completedAt) }),
      ...(item.completedBy === undefined
        ? {}
        : { completedBy: requireUuid(item.completedBy) }),
      id: requireUuid(item.id),
      title: requireString(item.title, 1, 512),
    };
  });
  if (!uniqueResourceIds(checklist)) throw projectionMismatch();
  const status = requireOneOf(value.status, taskStatuses);
  const hasCompletion =
    value.completedAt !== undefined && value.completedBy !== undefined;
  const terminal = status === "done" || status === "cancelled";
  const createdAt = requireInstant(value.createdAt);
  const updatedAt = requireInstant(value.updatedAt);
  if (
    terminal !== hasCompletion ||
    (!terminal && value.completionData !== undefined) ||
    (value.assigneeId !== undefined && value.operatorTeamId === undefined) ||
    Date.parse(updatedAt) < Date.parse(createdAt) ||
    (value.completedAt !== undefined &&
      (Date.parse(value.completedAt) < Date.parse(createdAt) ||
        Date.parse(value.completedAt) > Date.parse(updatedAt)))
  ) {
    throw projectionMismatch();
  }
  return {
    alertId,
    ...(value.assigneeId === undefined
      ? {}
      : { assigneeId: requireUuid(value.assigneeId) }),
    checklist,
    commentIds: [...value.commentIds],
    ...(value.completedAt === undefined
      ? {}
      : { completedAt: requireInstant(value.completedAt) }),
    ...(value.completedBy === undefined
      ? {}
      : { completedBy: requireUuid(value.completedBy) }),
    ...(value.completionData === undefined
      ? {}
      : { completionData: sanitizeDocument(value.completionData) }),
    createdAt,
    description: requireString(value.description, 0, 16_384),
    ...(value.dueAt === undefined
      ? {}
      : { dueAt: requireInstant(value.dueAt) }),
    id: value.id,
    ...(value.operatorTeamId === undefined
      ? {}
      : { operatorTeamId: requireUuid(value.operatorTeamId) }),
    priority: requireOneOf(value.priority, taskPriorities),
    ...(value.slaInstanceId === undefined
      ? {}
      : { slaInstanceId: requireUuid(value.slaInstanceId) }),
    status,
    tenantId,
    title: requireString(value.title, 1, 512),
    updatedAt,
    version: value.version,
  };
}

function sanitizeAttachment(
  value: DfirAttachment,
  tenantId: string,
  attachmentId: string,
): DfirAttachment {
  if (
    value.tenantId !== tenantId ||
    value.id !== attachmentId ||
    !validUuid(value.id) ||
    !validUuid(value.storageObjectId) ||
    !validUuid(value.uploadedBy)
  ) {
    throw projectionMismatch();
  }
  return {
    id: attachmentId,
    originalFilename: requireString(value.originalFilename, 1, 1_024),
    scanState: requireOneOf(value.scanState, scanStates),
    storageObjectId: value.storageObjectId,
    subject: sanitizeReference(value.subject),
    tenantId,
    uploadedAt: requireInstant(value.uploadedAt),
    uploadedBy: value.uploadedBy,
    visibility: requireOneOf(value.visibility, visibilityValues),
  };
}

function sanitizeRelationship(
  value: DfirAlertRelationship,
  tenantId: string,
  alertId: string,
): DfirAlertRelationship {
  if (
    !isRecord(value) ||
    value.tenantId !== tenantId ||
    value.alertId !== alertId ||
    !validUuid(value.id) ||
    !validVersion(value.version) ||
    !boundedArray(value.retractions, 1)
  ) {
    throw projectionMismatch();
  }
  const source = sanitizeReference(value.source);
  const target = sanitizeReference(value.target);
  const retractions = value.retractions.map((item) => ({
    actorId: requireUuid(item.actorId),
    id: requireUuid(item.id),
    occurredAt: requireInstant(item.occurredAt),
    reason: requireString(item.reason, 1, 2_000),
    sequence: requireInteger(item.sequence, 1, Number.MAX_SAFE_INTEGER),
  }));
  if (
    !uniqueResourceIds(retractions) ||
    retractions.some((item, index) => item.sequence !== index + 1) ||
    value.active !== (retractions.length === 0) ||
    value.version !== retractions.length + 1
  ) {
    throw projectionMismatch();
  }
  return {
    active: value.active,
    alertId,
    createdAt: requireInstant(value.createdAt),
    createdBy: requireUuid(value.createdBy),
    id: value.id,
    ...(value.metadata === undefined
      ? {}
      : { metadata: sanitizeDocument(value.metadata) }),
    relationshipType: requireString(
      value.relationshipType,
      1,
      64,
      stableKeyPattern,
    ),
    retractions,
    source,
    target,
    tenantId,
    version: value.version,
  };
}

function sanitizeReference(value: DfirEntityReference): DfirEntityReference {
  if (value.kind === "external") {
    if (value.id !== undefined || !value.externalType || !value.externalId) {
      throw projectionMismatch();
    }
    return {
      externalId: requireString(value.externalId, 1, 512),
      externalType: requireString(value.externalType, 1, 64, stableKeyPattern),
      kind: "external",
    };
  }
  if (
    (value.kind !== "alert" &&
      value.kind !== "case" &&
      value.kind !== "ioc" &&
      value.kind !== "asset" &&
      value.kind !== "evidence" &&
      value.kind !== "task" &&
      value.kind !== "attachment") ||
    !value.id ||
    !validUuid(value.id) ||
    value.externalId !== undefined ||
    value.externalType !== undefined
  ) {
    throw projectionMismatch();
  }
  return { id: value.id, kind: value.kind };
}

function isWorkspaceSubject(
  subject: DfirEntityReference,
  alertId: string,
  indicatorIds: ReadonlySet<string>,
  assetIds: ReadonlySet<string>,
  evidenceIds: ReadonlySet<string>,
  taskIds: ReadonlySet<string>,
): boolean {
  return (
    (subject.kind === "alert" && subject.id === alertId) ||
    (subject.kind === "ioc" &&
      Boolean(subject.id && indicatorIds.has(subject.id))) ||
    (subject.kind === "asset" &&
      Boolean(subject.id && assetIds.has(subject.id))) ||
    (subject.kind === "evidence" &&
      Boolean(subject.id && evidenceIds.has(subject.id))) ||
    (subject.kind === "task" && Boolean(subject.id && taskIds.has(subject.id)))
  );
}

function requireAlertSubject(
  subject: DfirEntityReference,
  alertId: string,
): void {
  const safe = sanitizeReference(subject);
  if (
    (safe.kind !== "alert" &&
      safe.kind !== "ioc" &&
      safe.kind !== "asset" &&
      safe.kind !== "evidence" &&
      safe.kind !== "task") ||
    (safe.kind === "alert" && safe.id !== alertId)
  ) {
    throw projectionMismatch();
  }
}

function validateVersionedResponse(
  value: {
    alertId: string;
    id: string;
    tenantId: string;
    version: number;
  },
  response: Response | undefined,
  tenantId: string,
  alertId: string,
  resourceId: string,
  requiresReplayHeader = false,
  expectedVersion?: number,
): void {
  validateAlertResource(value, tenantId, alertId, resourceId);
  if (
    response?.headers.get("ETag") !== strongVersionEtag(value.version) ||
    (requiresReplayHeader && !validReplayHeader(response)) ||
    (expectedVersion !== undefined && value.version !== expectedVersion + 1)
  ) {
    throw projectionMismatch();
  }
}

function validateRelationshipResponse(
  value: DfirAlertRelationship,
  response: Response | undefined,
  tenantId: string,
  alertId: string,
  relationshipId: string,
  expectedVersion?: number,
): void {
  const safe = sanitizeRelationship(value, tenantId, alertId);
  if (
    safe.id !== relationshipId ||
    response?.headers.get("ETag") !== strongVersionEtag(safe.version) ||
    !validReplayHeader(response) ||
    (expectedVersion !== undefined && safe.version !== expectedVersion + 1)
  ) {
    throw projectionMismatch();
  }
}

function validReplayHeader(response: Response | undefined): boolean {
  const replayed = response?.headers.get("X-Idempotent-Replay");
  return replayed === "true" || replayed === "false";
}

function validateAlertResource(
  value: { alertId: string; id: string; tenantId: string; version: number },
  tenantId: string,
  alertId: string,
  resourceId: string,
): void {
  if (
    !isRecord(value) ||
    value.tenantId !== tenantId ||
    value.alertId !== alertId ||
    value.id !== resourceId ||
    !validUuid(resourceId) ||
    !validVersion(value.version)
  ) {
    throw projectionMismatch();
  }
}

function sanitizePreparedUpload(
  value: DfirPreparedUpload,
  tenantId: string,
  request: DfirAttachmentUploadRequest,
): DfirPreparedUpload {
  const attachment = sanitizeAttachment(
    value.attachment,
    tenantId,
    request.attachmentId,
  );
  if (
    attachment.storageObjectId !== request.storageObjectId ||
    attachment.originalFilename !== request.originalFilename ||
    !sameReference(attachment.subject, request.subject) ||
    attachment.scanState !== "pending_upload" ||
    (request.requestedVisibility === "private" &&
      attachment.visibility !== "private") ||
    value.method !== "PUT" ||
    !boundedArray(value.headers, 32)
  ) {
    throw projectionMismatch();
  }
  validateCapabilityUrl(value.uploadUrl, value.expiresAt, 16 * 60_000);
  const seen = new Set<string>();
  const headers = value.headers.map(({ name, value: headerValue }) => {
    const safeName = requireString(name, 1, 128, /^[A-Za-z0-9-]+$/u);
    const safeValue = requireString(headerValue, 0, 4_096);
    const canonicalName = safeName.toLowerCase();
    if (seen.has(canonicalName) || hasHttpControlCharacter(safeValue)) {
      throw projectionMismatch();
    }
    seen.add(canonicalName);
    return { name: safeName, value: safeValue };
  });
  return {
    attachment,
    expiresAt: requireInstant(value.expiresAt),
    headers,
    method: "PUT",
    uploadUrl: value.uploadUrl,
  };
}

function sanitizePreparedDownload(
  value: DfirPreparedDownload,
  tenantId: string,
  attachmentId: string,
  request: DfirAttachmentDownloadRequest,
): DfirPreparedDownload {
  const attachment = sanitizeAttachment(
    value.attachment,
    tenantId,
    attachmentId,
  );
  if (
    attachment.scanState !== "available" ||
    !sameReference(attachment.subject, request.subject)
  ) {
    throw projectionMismatch();
  }
  validateCapabilityUrl(value.downloadUrl, value.expiresAt, 6 * 60_000);
  return {
    attachment,
    downloadUrl: value.downloadUrl,
    expiresAt: requireInstant(value.expiresAt),
  };
}

function validateCapabilityUrl(
  value: string,
  expiresAt: string,
  maximumLifetime = 16 * 60_000,
): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw projectionMismatch();
  }
  if (
    value.length > 8_192 ||
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    !validInstant(expiresAt) ||
    Date.parse(expiresAt) <= Date.now() ||
    Date.parse(expiresAt) > Date.now() + maximumLifetime
  ) {
    throw projectionMismatch();
  }
}

function sameReference(
  left: DfirEntityReference,
  right: DfirEntityReference,
): boolean {
  return (
    left.kind === right.kind &&
    left.id === right.id &&
    left.externalId === right.externalId &&
    left.externalType === right.externalType
  );
}

function referenceLabel(reference: DfirEntityReference): string {
  if (reference.kind === "external") {
    return `${reference.externalType ?? "external"}:${reference.externalId ?? "invalid"}`;
  }
  return `${reference.kind}:${compactIdentity(reference.id ?? "")}`;
}

function sanitizeDocument(value: object): { [key: string]: unknown } {
  validateDocumentValue(value, 1, { values: 0 });
  const serialized = JSON.stringify(value);
  if (
    serialized === undefined ||
    new TextEncoder().encode(serialized).byteLength > 65_536
  ) {
    throw projectionMismatch();
  }
  const copy: unknown = JSON.parse(serialized);
  if (!isRecord(copy)) throw projectionMismatch();
  return { ...copy };
}

function validateDocumentValue(
  value: unknown,
  depth: number,
  count: { values: number },
): void {
  count.values += 1;
  if (depth > 32 || count.values > 4_096) throw projectionMismatch();
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw projectionMismatch();
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 4_096) throw projectionMismatch();
    for (const item of value) validateDocumentValue(item, depth + 1, count);
    return;
  }
  if (!isRecord(value) || Object.keys(value).length > 200) {
    throw projectionMismatch();
  }
  for (const [key, item] of Object.entries(value)) {
    requireString(key, 1, 512);
    validateDocumentValue(item, depth + 1, count);
  }
}

function requireString(
  value: unknown,
  minimum: number,
  maximum: number,
  pattern?: RegExp,
): string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    throw projectionMismatch();
  }
  return value;
}

function requireBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw projectionMismatch();
  return value;
}

function requireInteger(
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

function requireInstant(value: unknown): string {
  if (typeof value !== "string" || !validInstant(value)) {
    throw projectionMismatch();
  }
  return value;
}

function requireUuid(value: unknown): string {
  if (typeof value !== "string" || !validUuid(value)) {
    throw projectionMismatch();
  }
  return value;
}

function requireDigest(value: unknown): string {
  if (typeof value !== "string" || !digestPattern.test(value)) {
    throw projectionMismatch();
  }
  return value;
}

function requireStringArray(
  value: unknown,
  maximumItems: number,
  uuid: boolean,
  maximumLength = 64,
  pattern?: RegExp,
): asserts value is string[] {
  if (!boundedArray(value, maximumItems)) throw projectionMismatch();
  const seen = new Set<string>();
  for (const item of value) {
    const safe = uuid
      ? requireUuid(item)
      : requireString(item, 1, maximumLength, pattern);
    if (seen.has(safe)) throw projectionMismatch();
    seen.add(safe);
  }
}

function requireOneOf<T extends string>(
  value: unknown,
  values: readonly T[],
): T {
  for (const candidate of values) {
    if (value === candidate) return candidate;
  }
  throw projectionMismatch();
}

function uniqueResourceIds(values: ReadonlyArray<{ id: string }>): boolean {
  return new Set(values.map(({ id }) => id)).size === values.length;
}

function compactIdentity(value: string): string {
  return validUuid(value)
    ? `${value.slice(0, 8)}…${value.slice(-4)}`
    : "invalid";
}

function boundedArray(value: unknown, maximum: number): value is unknown[] {
  return Array.isArray(value) && value.length <= maximum;
}

function validUuid(value: string): boolean {
  return uuidPattern.test(value);
}

function validVersion(value: number): boolean {
  return (
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= maximumDfirResourceVersion
  );
}

function validInstant(value: string): boolean {
  return (
    value.length <= 64 &&
    /(?:Z|[+-]\d{2}:\d{2})$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function hasHttpControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return true;
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function projectionMismatch(): AlertDfirApiError {
  return new AlertDfirApiError(
    "The Alert investigation response did not match its authorized projection.",
    503,
  );
}

function toApiError(response: Response | undefined): AlertDfirApiError {
  return new AlertDfirApiError(
    "The Alert investigation request could not be completed.",
    response?.status,
  );
}
