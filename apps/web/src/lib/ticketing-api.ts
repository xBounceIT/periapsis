import {
  archiveTenantTicketView,
  assignTenantAlert,
  assignTenantCase,
  claimTenantAlert,
  claimTenantCase,
  createTenantAlert,
  createTenantAlertComment,
  createTenantCase,
  createTenantCaseComment,
  createTenantTicketView,
  deleteTenantAlert,
  escalateTenantAlertToCase,
  linkTenantAlertToExistingCase,
  getTenantAlert,
  getTenantCase,
  getTenantTicketView,
  editTenantAlertComment,
  editTenantCaseComment,
  listTenantAlertActivities,
  listTenantAlertActivityFeed,
  listTenantAlertComments,
  listTenantAlertCustomerContacts,
  listTenantAlertLinkedCases,
  listTenantAlerts,
  listTenantCaseActivities,
  listTenantCaseActivityFeed,
  listTenantCaseComments,
  listTenantCaseLinkedAlerts,
  listTenantAlertCommentMentionCandidates,
  listTenantAlertCommentRevisions,
  listTenantCaseCommentMentionCandidates,
  listTenantCaseCommentRevisions,
  listTenantCases,
  listTenantTicketViews,
  releaseTenantAlert,
  releaseTenantCase,
  replaceTenantTicketView,
  previewTenantAlertComment,
  previewTenantCaseComment,
  restoreTenantTicketView,
  transferTenantAlert,
  transferTenantCase,
  transitionTenantAlert,
  transitionTenantCase,
  unlinkTenantAlertFromCase,
  type ActivityProjection,
  type AlertCaseEscalationRequest,
  type AlertCaseEscalationResult,
  type AlertCaseCopiedFieldSnapshot,
  type AlertCaseLinkView,
  type AlertCaseUnlinkReceipt,
  type AlertCaseUnlinkRequest,
  type AlertCreateRequest,
  type AlertDeleteReceipt,
  type AlertDeleteRequest,
  type AlertOperatorProjection,
  type AlertProjection,
  type AlertSeverity,
  type CaseCreateRequest,
  type CaseOperatorProjection,
  type CaseProjection,
  type CommentCreateRequest,
  type CommentEditRequest,
  type CommentMentionCandidate,
  type CustomerCommentAttachment,
  type OperatorCommentPreview,
  type OperatorCommentAttachment,
  type OperatorCommentMention,
  type OperatorCommentRevision,
  type OperatorComment,
  type CustomerComment,
  type EscalationCopySelection,
  type AppliedSavedTicketView,
  type TicketAssignmentRequest,
  type TicketClaimRequest,
  type TicketCustomerContactLink,
  type TicketPriority,
  type SavedTicketView,
  type SavedTicketViewCreateRequest,
  type SavedTicketViewLifecycleRequest,
  type SavedTicketViewReplaceRequest,
  type TicketReleaseRequest,
  type TicketSort,
  type TicketTransferRequest,
  type TicketTransitionRequest,
} from "@periapsis/contracts";

import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
  isCanonicalDisplayName,
} from "./canonical-display-name";
import {
  hasBidiControlCharacters,
  hasControlCharacters,
  hasForbiddenCommentMarkdownCharacters,
} from "./text-validation";
import { parseRfc3339Instant } from "./rfc3339-instant";
import { sessionAwareFetch } from "./session-transition-transport";

export type TicketKind = "alert" | "case";
export type TicketProjection = AlertProjection | CaseProjection;
export type OperatorTicketProjection =
  AlertOperatorProjection | CaseOperatorProjection;

export interface VersionedTicket<
  T extends TicketProjection = TicketProjection,
> {
  etag: string;
  value: T;
}

export interface TicketListFilters {
  after?: string;
  customerVisible?: boolean;
  limit?: number;
  priority?: TicketPriority[];
  queue?: "assigned_to_me" | "my_operator_teams" | "unassigned";
  search?: string;
  severity?: AlertSeverity[];
  sort?: TicketSort;
  status?: string[];
  viewId?: string;
}

export interface TicketPage {
  appliedView?: AppliedSavedTicketView;
  items: TicketProjection[];
  nextCursor?: string;
}

export interface VersionedSavedTicketView {
  etag: string;
  value: SavedTicketView;
}

export interface SavedTicketViewPageView {
  items: SavedTicketView[];
  nextCursor?: string;
}

export interface SavedTicketViewMutationView extends VersionedSavedTicketView {
  replayed: boolean;
}

export type TicketComment =
  Omit<OperatorComment, "bodyHtml"> | Omit<CustomerComment, "bodyHtml">;
export type TicketCommentPreview = Omit<OperatorCommentPreview, "bodyHtml">;
export type TicketCommentRevision = Omit<OperatorCommentRevision, "bodyHtml">;

export interface CommentRevisionPage {
  items: TicketCommentRevision[];
  nextAfterRevision?: number;
}

export interface VersionedCommentMutation {
  etag: string;
  replayed: boolean;
  value: Extract<TicketComment, { projection: "operator" }>;
}
type OperatorActivityActorProjection = Extract<
  ActivityProjection,
  { projection: "operator" }
>["actor"];

export interface CursorPage<T> {
  items: T[];
  nextCursor?: string;
}

interface MutationCommon {
  csrfToken: string;
  etag: string;
  kind: TicketKind;
  resourceId: string;
  tenantId: string;
}

export type TicketMutationCommand =
  | (MutationCommon & {
      action: "assign";
      body: TicketAssignmentRequest;
    })
  | (MutationCommon & {
      action: "claim";
      body: TicketClaimRequest;
    })
  | (MutationCommon & {
      action: "release";
      body: TicketReleaseRequest;
    })
  | (MutationCommon & {
      action: "transfer";
      body: TicketTransferRequest;
    })
  | (MutationCommon & {
      action: "transition";
      body: TicketTransitionRequest;
      idempotencyKey: string;
    });

export interface TicketingApi {
  createAlert(input: {
    body: AlertCreateRequest;
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<{ etag: string; id: string; version: number }>;
  createCase(input: {
    body: CaseCreateRequest;
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<VersionedTicket<CaseOperatorProjection>>;
  createComment(input: {
    body: CommentCreateRequest;
    csrfToken: string;
    idempotencyKey: string;
    kind: TicketKind;
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketComment>;
  previewComment(input: {
    body: CommentCreateRequest;
    csrfToken: string;
    kind: TicketKind;
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketCommentPreview>;
  listCommentMentionCandidates(input: {
    kind: TicketKind;
    resourceId: string;
    search?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CommentMentionCandidate[]>;
  editComment(input: {
    body: CommentEditRequest;
    commentId: string;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    kind: TicketKind;
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<VersionedCommentMutation>;
  listCommentRevisions(input: {
    afterRevision?: number;
    commentId: string;
    kind: TicketKind;
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CommentRevisionPage>;
  deleteAlert(input: {
    body: AlertDeleteRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    resourceId: string;
    tenantId: string;
  }): Promise<AlertDeleteReceipt>;
  escalateAlert(input: {
    body: AlertCaseEscalationRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    resourceId: string;
    tenantId: string;
  }): Promise<AlertCaseEscalationResult>;
  unlinkAlertCase(input: {
    body: AlertCaseUnlinkRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<AlertCaseUnlinkReceipt>;
  getTicket(
    kind: TicketKind,
    tenantId: string,
    resourceId: string,
    signal?: AbortSignal,
  ): Promise<VersionedTicket>;
  listActivities(
    kind: TicketKind,
    tenantId: string,
    resourceId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<CursorPage<ActivityProjection>>;
  listActivityFeed(
    kind: TicketKind,
    tenantId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<
    CursorPage<Extract<ActivityProjection, { projection: "operator" }>>
  >;
  listComments(
    kind: TicketKind,
    tenantId: string,
    resourceId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<CursorPage<TicketComment>>;
  listAlertContactLinks(
    tenantId: string,
    alertId: string,
    signal?: AbortSignal,
  ): Promise<CursorPage<TicketCustomerContactLink>>;
  listLinks(
    kind: TicketKind,
    tenantId: string,
    resourceId: string,
    after?: string,
    signal?: AbortSignal,
  ): Promise<CursorPage<AlertCaseLinkView>>;
  listTickets(
    kind: TicketKind,
    tenantId: string,
    filters: TicketListFilters,
    signal?: AbortSignal,
  ): Promise<TicketPage>;
  listSavedTicketViews(input: {
    after?: string;
    includeArchived?: boolean;
    kind: TicketKind;
    tenantId: string;
    signal?: AbortSignal;
  }): Promise<SavedTicketViewPageView>;
  getSavedTicketView(input: {
    kind: TicketKind;
    tenantId: string;
    viewId: string;
    signal?: AbortSignal;
  }): Promise<VersionedSavedTicketView>;
  createSavedTicketView(input: {
    body: SavedTicketViewCreateRequest;
    csrfToken: string;
    idempotencyKey: string;
    tenantId: string;
  }): Promise<SavedTicketViewMutationView>;
  replaceSavedTicketView(input: {
    body: SavedTicketViewReplaceRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    viewId: string;
  }): Promise<SavedTicketViewMutationView>;
  archiveSavedTicketView(input: {
    body: SavedTicketViewLifecycleRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    viewId: string;
  }): Promise<SavedTicketViewMutationView>;
  restoreSavedTicketView(input: {
    body: SavedTicketViewLifecycleRequest;
    csrfToken: string;
    etag: string;
    idempotencyKey: string;
    tenantId: string;
    viewId: string;
  }): Promise<SavedTicketViewMutationView>;
  mutateTicket(
    command: TicketMutationCommand,
  ): Promise<VersionedTicket<OperatorTicketProjection>>;
}

interface GeneratedResult<T> {
  data?: T | undefined;
  error?: unknown;
  response?: Response | undefined;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const strongEntityTagPattern = /^"v([1-9]\d{0,9})"$/;
const savedViewEntityTagPattern = /^"sha256-[0-9a-f]{64}"$/u;
const savedViewDigestPattern = /^[0-9a-f]{64}$/u;
const savedViewCursorPattern = /^[A-Za-z0-9_-]{22}$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}(?![\s\S])/u;
const commentEntityTagPattern = /^"comment-r([1-9]\d{0,9})"(?![\s\S])/u;
const workflowKeyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const customFieldKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const ticketTagPattern = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$/u;
const alertSeverities = new Set([
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);
const ticketPriorities = new Set([
  "low",
  "medium",
  "high",
  "urgent",
  "critical",
]);
const customerActivityKinds = new Set([
  "created",
  "status_changed",
  "escalated",
  "linked",
  "unlinked",
  "comment.public",
]);
const operatorActivityKinds = new Set([
  "created",
  "transitioned",
  "assigned",
  "claimed",
  "released",
  "transferred",
  "escalated",
  "linked",
  "unlinked",
  "comment.public",
  "comment.private",
]);
const escalationCopyFields = new Set([
  "title",
  "description",
  "severity",
  "priority",
  "category",
  "tags",
]);

type SafeCustomFieldValue =
  boolean | null | number | string | Array<boolean | number | string>;
type SafeCustomFieldValues = Record<string, SafeCustomFieldValue>;

export const ticketingApi: TicketingApi = {
  async listTickets(kind, tenantId, filters, signal) {
    const viewId = canonicalSavedViewId(filters.viewId);
    if (
      filters.viewId !== undefined &&
      (viewId === undefined || hasInlineTicketFilters(filters))
    ) {
      throw projectionMismatch(
        "A saved view cannot be combined with inline ticket filters.",
      );
    }
    const options = {
      ...sameOrigin,
      path: { tenantId },
      query: {
        limit: filters.limit ?? 30,
        ...(filters.after ? { after: filters.after } : {}),
        ...(viewId === undefined
          ? {
              ...(filters.customerVisible === undefined
                ? {}
                : { customerVisible: filters.customerVisible }),
              ...(filters.priority?.length
                ? { priority: filters.priority }
                : {}),
              ...(filters.queue ? { queue: filters.queue } : {}),
              ...(filters.search ? { search: filters.search } : {}),
              ...(filters.severity?.length
                ? { severity: filters.severity }
                : {}),
              ...(filters.sort ? { sort: filters.sort } : {}),
              ...(filters.status?.length ? { status: filters.status } : {}),
            }
          : { viewId }),
      },
      ...(signal ? { signal } : {}),
    };
    const page: unknown =
      kind === "alert"
        ? unwrap(await listTenantAlerts(options))
        : unwrap(await listTenantCases(options));
    return projectTicketPage(page, kind, tenantId, viewId);
  },

  async listSavedTicketViews({
    after,
    includeArchived,
    kind,
    signal,
    tenantId,
  }) {
    if (after !== undefined && !isCanonicalSavedViewCursor(after)) {
      throw projectionMismatch(
        "The saved-view cursor was not a canonical UUIDv7 position.",
      );
    }
    const result = await listTenantTicketViews({
      ...sameOrigin,
      path: { tenantId },
      query: {
        kind,
        limit: 100,
        ...(after ? { after } : {}),
        ...(includeArchived === undefined ? {} : { includeArchived }),
      },
      ...(signal ? { signal } : {}),
    });
    return projectSavedTicketViewPage(unwrap(result), tenantId, kind);
  },

  async getSavedTicketView({ kind, signal, tenantId, viewId }) {
    requireCanonicalSavedViewId(viewId);
    const result = await getTenantTicketView({
      ...sameOrigin,
      path: { tenantId, viewId },
      query: { kind },
      ...(signal ? { signal } : {}),
    });
    const value = projectSavedTicketView(
      unwrap(result),
      tenantId,
      kind,
      viewId,
    );
    return { etag: requireSavedViewEtag(result.response), value };
  },

  async createSavedTicketView({ body, csrfToken, idempotencyKey, tenantId }) {
    requireSavedViewMutationContext(csrfToken, idempotencyKey, tenantId);
    requireSavedViewCreateRequest(body);
    const result = await createTenantTicketView({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    const projected = projectSavedTicketViewMutation(
      result,
      tenantId,
      body.kind,
    );
    const expectedLocation = `/api/v1/tenants/${tenantId}/ticket-views/${projected.value.id}`;
    if (result.response?.headers.get("Location") !== expectedLocation) {
      throw projectionMismatch(
        "The saved-view creation location was not canonical.",
      );
    }
    return projected;
  },

  async replaceSavedTicketView({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    tenantId,
    viewId,
  }) {
    requireSavedViewMutationContext(csrfToken, idempotencyKey, tenantId);
    requireCanonicalSavedViewId(viewId);
    requireSavedViewEtagValue(etag);
    requireSavedViewReplaceRequest(body);
    const result = await replaceTenantTicketView({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId, viewId },
    });
    return projectSavedTicketViewMutation(result, tenantId, body.kind, viewId);
  },

  async archiveSavedTicketView({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    tenantId,
    viewId,
  }) {
    requireSavedViewMutationContext(csrfToken, idempotencyKey, tenantId);
    requireCanonicalSavedViewId(viewId);
    requireSavedViewEtagValue(etag);
    requireSavedViewLifecycleRequest(body);
    const result = await archiveTenantTicketView({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId, viewId },
    });
    return projectSavedTicketViewMutation(result, tenantId, body.kind, viewId);
  },

  async restoreSavedTicketView({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    tenantId,
    viewId,
  }) {
    requireSavedViewMutationContext(csrfToken, idempotencyKey, tenantId);
    requireCanonicalSavedViewId(viewId);
    requireSavedViewEtagValue(etag);
    requireSavedViewLifecycleRequest(body);
    const result = await restoreTenantTicketView({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId, viewId },
    });
    return projectSavedTicketViewMutation(result, tenantId, body.kind, viewId);
  },

  async getTicket(kind, tenantId, resourceId, signal) {
    return kind === "alert"
      ? unwrapVersionedTicket(
          await getTenantAlert({
            ...sameOrigin,
            path: { alertId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          }),
          kind,
          tenantId,
          resourceId,
        )
      : unwrapVersionedTicket(
          await getTenantCase({
            ...sameOrigin,
            path: { caseId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          }),
          kind,
          tenantId,
          resourceId,
        );
  },

  async createAlert({ body, csrfToken, idempotencyKey, tenantId }) {
    const result = await createTenantAlert({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    const alert = unwrap(result);
    if (
      !isRecord(alert) ||
      alert["tenantId"] !== tenantId ||
      typeof alert["id"] !== "string" ||
      !isResourceVersion(alert["version"])
    ) {
      throw projectionMismatch();
    }
    return {
      etag: requireVersionEtag(result.response, alert["version"]),
      id: alert["id"],
      version: alert["version"],
    };
  },

  async createCase({ body, csrfToken, idempotencyKey, tenantId }) {
    const result = await createTenantCase({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    const created = unwrapOperatorTicket(result, "case", tenantId);
    if (!("caseNumber" in created.value)) throw projectionMismatch();
    return { etag: created.etag, value: created.value };
  },

  async deleteAlert({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    resourceId,
    tenantId,
  }) {
    requireTicketMutationContext(
      csrfToken,
      etag,
      idempotencyKey,
      resourceId,
      tenantId,
      body.expectedVersion,
    );
    const result = await deleteTenantAlert({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { alertId: resourceId, tenantId },
    });
    const value = unwrap(result as GeneratedResult<unknown>);
    if (
      !isRecord(value) ||
      value["tenantId"] !== tenantId ||
      value["alertId"] !== resourceId ||
      value["previousVersion"] !== body.expectedVersion ||
      !isResourceVersion(value["tombstoneVersion"]) ||
      value["tombstoneVersion"] !== body.expectedVersion + 1 ||
      !isCanonicalInstant(value["deletedAt"]) ||
      typeof value["replayed"] !== "boolean"
    ) {
      throw projectionMismatch();
    }
    requireVersionEtag(result.response, value["tombstoneVersion"]);
    return {
      alertId: value["alertId"],
      deletedAt: value["deletedAt"],
      previousVersion: value["previousVersion"],
      replayed: value["replayed"],
      tenantId: value["tenantId"],
      tombstoneVersion: value["tombstoneVersion"],
    };
  },

  async mutateTicket(command) {
    const commonHeaders = {
      "If-Match": command.etag,
      "X-CSRF-Token": command.csrfToken,
    };
    let result: GeneratedResult<unknown>;

    if (command.kind === "alert") {
      const path = {
        alertId: command.resourceId,
        tenantId: command.tenantId,
      };
      switch (command.action) {
        case "assign":
          result = await assignTenantAlert({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "claim":
          result = await claimTenantAlert({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          result = claimTicketResult(result, "alert");
          break;
        case "release":
          result = await releaseTenantAlert({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "transfer":
          result = await transferTenantAlert({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "transition":
          result = await transitionTenantAlert({
            ...sameOrigin,
            body: command.body,
            headers: {
              ...commonHeaders,
              "Idempotency-Key": command.idempotencyKey,
            },
            path,
          });
          break;
      }
    } else {
      const path = {
        caseId: command.resourceId,
        tenantId: command.tenantId,
      };
      switch (command.action) {
        case "assign":
          result = await assignTenantCase({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "claim":
          result = await claimTenantCase({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          result = claimTicketResult(result, "case");
          break;
        case "release":
          result = await releaseTenantCase({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "transfer":
          result = await transferTenantCase({
            ...sameOrigin,
            body: command.body,
            headers: commonHeaders,
            path,
          });
          break;
        case "transition":
          result = await transitionTenantCase({
            ...sameOrigin,
            body: command.body,
            headers: {
              ...commonHeaders,
              "Idempotency-Key": command.idempotencyKey,
            },
            path,
          });
          break;
      }
    }

    return unwrapOperatorTicket(
      result,
      command.kind,
      command.tenantId,
      command.resourceId,
    );
  },

  async escalateAlert({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    resourceId,
    tenantId,
  }) {
    const headers = {
      "Idempotency-Key": idempotencyKey,
      "If-Match": etag,
      "X-CSRF-Token": csrfToken,
    };
    const path = { alertId: resourceId, tenantId };
    const result =
      body.target.mode === "existing_case"
        ? await linkTenantAlertToExistingCase({
            ...sameOrigin,
            body: { ...body, target: body.target },
            headers,
            path,
          })
        : await escalateTenantAlertToCase({
            ...sameOrigin,
            body,
            headers,
            path,
          });
    const value = unwrap(result as GeneratedResult<unknown>);
    if (!isRecord(value) || !isTicketSideEffectPlan(value["sideEffects"])) {
      throw projectionMismatch();
    }
    const alert = projectTicket("alert", tenantId, resourceId, value["alert"]);
    const targetCase = projectTicket(
      "case",
      tenantId,
      undefined,
      value["case"],
    );
    if (
      alert.projection !== "operator" ||
      !("alertNumber" in alert) ||
      targetCase.projection !== "operator" ||
      !("caseNumber" in targetCase)
    ) {
      throw projectionMismatch();
    }
    requireVersionEtag(result.response, alert.version);
    const links = Array.isArray(value["links"])
      ? value["links"].map((link) =>
          projectLink(tenantId, resourceId, "alert", link),
        )
      : [];
    const operatorLinks = links.filter(isOperatorAlertCaseLink);
    if (
      links.length !==
        (Array.isArray(value["links"]) ? value["links"].length : -1) ||
      operatorLinks.length !== links.length ||
      hasDuplicateAlertCaseLinks(operatorLinks) ||
      operatorLinks.some((link) => link.caseId !== targetCase.id)
    ) {
      throw projectionMismatch();
    }
    return {
      alert,
      case: targetCase,
      links: operatorLinks,
      sideEffects: value["sideEffects"],
    };
  },

  async unlinkAlertCase({
    body,
    csrfToken,
    etag,
    idempotencyKey,
    resourceId,
    signal,
    tenantId,
  }) {
    const result = await unlinkTenantAlertFromCase({
      ...sameOrigin,
      body,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      path: { alertId: resourceId, tenantId },
      ...(signal === undefined ? {} : { signal }),
    });
    const value = unwrap(result as GeneratedResult<unknown>);
    if (!isAlertCaseUnlinkReceipt(value, tenantId, resourceId, body)) {
      throw projectionMismatch();
    }
    requireVersionEtag(result.response, value.alertVersion);
    return value;
  },

  async listComments(kind, tenantId, resourceId, after, signal) {
    requireCommentCoordinates(kind, tenantId, resourceId);
    if (after !== undefined && !uuidV7Pattern.test(after)) {
      throw projectionMismatch(
        "The comment cursor was not a canonical UUIDv7.",
      );
    }
    const result =
      kind === "alert"
        ? await listTenantAlertComments({
            ...sameOrigin,
            cache: "no-store",
            path: { alertId: resourceId, tenantId },
            query: { ...(after ? { after } : {}), limit: 50 },
            ...(signal ? { signal } : {}),
          })
        : await listTenantCaseComments({
            ...sameOrigin,
            cache: "no-store",
            path: { caseId: resourceId, tenantId },
            query: { ...(after ? { after } : {}), limit: 50 },
            ...(signal ? { signal } : {}),
          });
    return projectOperatorCommentPage(
      unwrap(result),
      kind,
      tenantId,
      resourceId,
    );
  },

  async listAlertContactLinks(tenantId, alertId, signal) {
    const page = unwrap(
      await listTenantAlertCustomerContacts({
        ...sameOrigin,
        path: { alertId, tenantId },
        query: { limit: 100 },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectAlertContactLinkPage(page, tenantId, alertId);
  },

  async createComment({
    body,
    csrfToken,
    idempotencyKey,
    kind,
    resourceId,
    signal,
    tenantId,
  }) {
    requireCommentCoordinates(kind, tenantId, resourceId);
    requireCommentMutationHeaders(csrfToken, idempotencyKey);
    requireCommentCreateRequest(body);
    const headers = {
      "Idempotency-Key": idempotencyKey,
      "X-CSRF-Token": csrfToken,
    };
    const result =
      kind === "alert"
        ? await createTenantAlertComment({
            ...sameOrigin,
            cache: "no-store",
            body,
            headers,
            path: { alertId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          })
        : await createTenantCaseComment({
            ...sameOrigin,
            cache: "no-store",
            body,
            headers,
            path: { caseId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          });
    const comment = projectComment(kind, tenantId, resourceId, unwrap(result));
    if (comment.projection !== "operator") {
      throw projectionMismatch(
        "The operator comment route returned a customer projection.",
      );
    }
    requireCommentResponseEtag(result.response, comment.revision);
    requireReplayHeader(result.response);
    return comment;
  },

  async previewComment({
    body,
    csrfToken,
    kind,
    resourceId,
    signal,
    tenantId,
  }) {
    requireCommentCoordinates(kind, tenantId, resourceId);
    requireCsrfToken(csrfToken);
    requireCommentCreateRequest(body);
    const request = {
      ...sameOrigin,
      body,
      cache: "no-store" as const,
      headers: { "X-CSRF-Token": csrfToken },
      ...(signal ? { signal } : {}),
    };
    const value: unknown = unwrap(
      kind === "alert"
        ? await previewTenantAlertComment({
            ...request,
            path: { alertId: resourceId, tenantId },
          })
        : await previewTenantCaseComment({
            ...request,
            path: { caseId: resourceId, tenantId },
          }),
    );
    return projectOperatorCommentPreview(value, body.visibility);
  },

  async listCommentMentionCandidates({
    kind,
    resourceId,
    search,
    signal,
    tenantId,
  }) {
    requireCommentCoordinates(kind, tenantId, resourceId);
    if (search !== undefined && !isBoundedCommentSearch(search)) {
      throw projectionMismatch("The mention search was not bounded.");
    }
    const request = {
      ...sameOrigin,
      cache: "no-store" as const,
      query: { limit: 100, ...(search ? { search } : {}) },
      ...(signal ? { signal } : {}),
    };
    const value: unknown = unwrap(
      kind === "alert"
        ? await listTenantAlertCommentMentionCandidates({
            ...request,
            path: { alertId: resourceId, tenantId },
          })
        : await listTenantCaseCommentMentionCandidates({
            ...request,
            path: { caseId: resourceId, tenantId },
          }),
    );
    return projectCommentMentionCandidates(value);
  },

  async editComment({
    body,
    commentId,
    csrfToken,
    etag,
    idempotencyKey,
    kind,
    resourceId,
    signal,
    tenantId,
  }) {
    requireCommentCoordinates(kind, tenantId, resourceId, commentId);
    requireCommentMutationHeaders(csrfToken, idempotencyKey);
    const expectedRevision = requireCommentEtag(etag);
    requireCommentEditRequest(body);
    const request = {
      ...sameOrigin,
      body,
      cache: "no-store" as const,
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": etag,
        "X-CSRF-Token": csrfToken,
      },
      ...(signal ? { signal } : {}),
    };
    const result =
      kind === "alert"
        ? await editTenantAlertComment({
            ...request,
            path: { alertId: resourceId, commentId, tenantId },
          })
        : await editTenantCaseComment({
            ...request,
            path: { caseId: resourceId, commentId, tenantId },
          });
    const value = projectComment(kind, tenantId, resourceId, unwrap(result));
    if (
      value.projection !== "operator" ||
      value.id !== commentId ||
      value.revision !== expectedRevision + 1
    ) {
      throw projectionMismatch(
        "The edited comment projection did not match the request.",
      );
    }
    const responseEtag = requireCommentResponseEtag(
      result.response,
      value.revision,
    );
    const replayed = requireReplayHeader(result.response);
    return { etag: responseEtag, replayed, value };
  },

  async listCommentRevisions({
    afterRevision,
    commentId,
    kind,
    resourceId,
    signal,
    tenantId,
  }) {
    requireCommentCoordinates(kind, tenantId, resourceId, commentId);
    if (afterRevision !== undefined && !isResourceVersion(afterRevision)) {
      throw projectionMismatch("The comment revision cursor was invalid.");
    }
    const request = {
      ...sameOrigin,
      cache: "no-store" as const,
      query: { limit: 100, ...(afterRevision ? { afterRevision } : {}) },
      ...(signal ? { signal } : {}),
    };
    const value: unknown = unwrap(
      kind === "alert"
        ? await listTenantAlertCommentRevisions({
            ...request,
            path: { alertId: resourceId, commentId, tenantId },
          })
        : await listTenantCaseCommentRevisions({
            ...request,
            path: { caseId: resourceId, commentId, tenantId },
          }),
    );
    return projectOperatorCommentRevisionPage(value, afterRevision);
  },

  async listActivities(kind, tenantId, resourceId, after, signal) {
    const page =
      kind === "alert"
        ? unwrap(
            await listTenantAlertActivities({
              ...sameOrigin,
              path: { alertId: resourceId, tenantId },
              query: { ...(after ? { after } : {}), limit: 50 },
              ...(signal ? { signal } : {}),
            }),
          )
        : unwrap(
            await listTenantCaseActivities({
              ...sameOrigin,
              path: { caseId: resourceId, tenantId },
              query: { ...(after ? { after } : {}), limit: 50 },
              ...(signal ? { signal } : {}),
            }),
          );
    return projectCursorPage(page, (item) =>
      projectActivity(kind, tenantId, resourceId, item),
    );
  },

  async listActivityFeed(kind, tenantId, after, signal) {
    const request = {
      ...sameOrigin,
      path: { tenantId },
      query: { ...(after ? { after } : {}), limit: 50 },
      ...(signal ? { signal } : {}),
    };
    const page = unwrap(
      kind === "alert"
        ? await listTenantAlertActivityFeed(request)
        : await listTenantCaseActivityFeed(request),
    );
    return projectGlobalActivityPage(page, kind, tenantId);
  },

  async listLinks(kind, tenantId, resourceId, after, signal) {
    const page =
      kind === "alert"
        ? unwrap(
            await listTenantAlertLinkedCases({
              ...sameOrigin,
              path: { alertId: resourceId, tenantId },
              query: { ...(after ? { after } : {}), limit: 50 },
              ...(signal ? { signal } : {}),
            }),
          )
        : unwrap(
            await listTenantCaseLinkedAlerts({
              ...sameOrigin,
              path: { caseId: resourceId, tenantId },
              query: { ...(after ? { after } : {}), limit: 50 },
              ...(signal ? { signal } : {}),
            }),
          );
    return projectAlertCaseLinkPage(page, tenantId, resourceId, kind);
  },
};

function hasInlineTicketFilters(filters: TicketListFilters): boolean {
  return (
    filters.customerVisible !== undefined ||
    Boolean(filters.priority?.length) ||
    filters.queue !== undefined ||
    filters.search !== undefined ||
    Boolean(filters.severity?.length) ||
    filters.sort !== undefined ||
    Boolean(filters.status?.length)
  );
}

function projectTicketPage(
  value: unknown,
  kind: TicketKind,
  tenantId: string,
  expectedViewId?: string,
): TicketPage {
  if (
    !isRecord(value) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        value["nextCursor"].length === 0 ||
        value["nextCursor"].length > 4096))
  ) {
    throw projectionMismatch();
  }
  const applied = value["appliedView"];
  if (expectedViewId === undefined) {
    if (applied !== undefined) throw projectionMismatch();
  } else if (!isAppliedSavedTicketView(applied, expectedViewId)) {
    throw projectionMismatch(
      "The backend did not prove the selected saved view was applied.",
    );
  }
  const items = value["items"].map((item) =>
    projectTicket(kind, tenantId, undefined, item),
  );
  if (
    items.some((item) =>
      expectedViewId === undefined
        ? item.projection === "operator" && item.dynamicColumns !== undefined
        : item.projection !== "operator",
    )
  ) {
    throw projectionMismatch();
  }
  const page = {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
  if (expectedViewId === undefined) return page;
  if (!isAppliedSavedTicketView(applied, expectedViewId)) {
    throw projectionMismatch(
      "The backend did not prove the selected saved view was applied.",
    );
  }
  return { ...page, appliedView: applied };
}

function isAppliedSavedTicketView(
  value: unknown,
  expectedViewId: string,
): value is AppliedSavedTicketView {
  return (
    isRecord(value) &&
    value["id"] === expectedViewId &&
    isResourceVersion(value["revision"]) &&
    typeof value["specSha256"] === "string" &&
    savedViewDigestPattern.test(value["specSha256"])
  );
}

function projectSavedTicketViewPage(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
): SavedTicketViewPageView {
  if (
    !isRecord(value) ||
    !hasExactObjectKeys(value, ["items", "nextCursor"]) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        !isCanonicalSavedViewCursor(value["nextCursor"])))
  ) {
    throw projectionMismatch();
  }
  const items = value["items"].map((item) =>
    projectSavedTicketView(item, tenantId, kind),
  );
  if (
    items.some((item, index) => index > 0 && items[index - 1]!.id >= item.id) ||
    (typeof value["nextCursor"] === "string" &&
      (items.length === 0 ||
        value["nextCursor"] !== savedViewCursorForId(items.at(-1)!.id)))
  ) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function savedViewCursorForId(identifier: string): string {
  const bytes = identifier
    .replaceAll("-", "")
    .match(/.{2}/gu)
    ?.map((pair) => String.fromCodePoint(Number.parseInt(pair, 16)))
    .join("");
  if (bytes === undefined) throw projectionMismatch();
  return encodeBase64Url(bytes);
}

function encodeBase64Url(bytes: string): string {
  return globalThis
    .btoa(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function isCanonicalSavedViewCursor(value: string): boolean {
  if (!savedViewCursorPattern.test(value)) return false;
  try {
    const bytes = globalThis.atob(
      `${value.replaceAll("-", "+").replaceAll("_", "/")}==`,
    );
    return (
      bytes.length === 16 &&
      (bytes.codePointAt(6)! & 0xf0) === 0x70 &&
      (bytes.codePointAt(8)! & 0xc0) === 0x80 &&
      encodeBase64Url(bytes) === value
    );
  } catch {
    return false;
  }
}

function projectSavedTicketViewMutation(
  result: GeneratedResult<unknown>,
  tenantId: string,
  kind: TicketKind,
  expectedViewId?: string,
): SavedTicketViewMutationView {
  const value = unwrap(result);
  if (!isRecord(value) || typeof value["replayed"] !== "boolean") {
    throw projectionMismatch();
  }
  return {
    etag: requireSavedViewEtag(result.response),
    replayed: value["replayed"],
    value: projectSavedTicketView(
      value["view"],
      tenantId,
      kind,
      expectedViewId,
    ),
  };
}

function projectSavedTicketView(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
  expectedViewId?: string,
): SavedTicketView {
  if (
    !isRecord(value) ||
    typeof value["id"] !== "string" ||
    !uuidV7Pattern.test(value["id"]) ||
    (expectedViewId !== undefined && value["id"] !== expectedViewId) ||
    value["tenantId"] !== tenantId ||
    typeof value["ownerMembershipId"] !== "string" ||
    !uuidV7Pattern.test(value["ownerMembershipId"]) ||
    value["kind"] !== kind ||
    !isSavedViewInputText(value["name"], 120) ||
    (value["status"] !== "active" && value["status"] !== "archived") ||
    !isResourceVersion(value["revision"]) ||
    !isSavedTicketViewSpec(value["spec"], tenantId, kind) ||
    typeof value["specSha256"] !== "string" ||
    !savedViewDigestPattern.test(value["specSha256"]) ||
    !isCanonicalInstant(value["createdAt"]) ||
    !isCanonicalInstant(value["updatedAt"]) ||
    (value["archivedAt"] !== undefined &&
      !isCanonicalInstant(value["archivedAt"])) ||
    (value["status"] === "archived") !==
      (typeof value["archivedAt"] === "string")
  ) {
    throw projectionMismatch();
  }
  return {
    id: value["id"],
    tenantId,
    ownerMembershipId: value["ownerMembershipId"],
    kind,
    name: value["name"],
    status: value["status"],
    revision: value["revision"],
    spec: cloneSavedTicketViewSpec(value["spec"]),
    specSha256: value["specSha256"],
    createdAt: value["createdAt"],
    updatedAt: value["updatedAt"],
    ...(typeof value["archivedAt"] === "string"
      ? { archivedAt: value["archivedAt"] }
      : {}),
  };
}

function requireSavedViewCreateRequest(
  value: SavedTicketViewCreateRequest,
): void {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["kind", "name", "spec"]) ||
    (value["kind"] !== "alert" && value["kind"] !== "case") ||
    !isSavedViewInputText(value["name"], 120) ||
    !isSavedTicketViewSpecInput(value["spec"])
  ) {
    throw projectionMismatch(
      "The saved-view create command was not canonical.",
    );
  }
}

function requireSavedViewReplaceRequest(
  value: SavedTicketViewReplaceRequest,
): void {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["expectedRevision", "kind", "name", "spec"]) ||
    (value["kind"] !== "alert" && value["kind"] !== "case") ||
    !isSavedViewExpectedRevision(value["expectedRevision"]) ||
    !isSavedViewInputText(value["name"], 120) ||
    !isSavedTicketViewSpecInput(value["spec"])
  ) {
    throw projectionMismatch(
      "The saved-view replacement command was not canonical.",
    );
  }
}

function requireSavedViewLifecycleRequest(
  value: SavedTicketViewLifecycleRequest,
): void {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["expectedRevision", "kind"]) ||
    (value["kind"] !== "alert" && value["kind"] !== "case") ||
    !isSavedViewExpectedRevision(value["expectedRevision"])
  ) {
    throw projectionMismatch(
      "The saved-view lifecycle command was not canonical.",
    );
  }
}

export function isSavedTicketViewSpecInput(
  value: unknown,
): value is SavedTicketViewCreateRequest["spec"] {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["columns", "filters", "sort"]) ||
    !isRecord(value["filters"]) ||
    !isRecord(value["sort"]) ||
    !Array.isArray(value["columns"]) ||
    value["columns"].length < 1 ||
    value["columns"].length > 64
  ) {
    return false;
  }
  const filters = value["filters"];
  if (
    !hasOnlyKeys(filters, [
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
    ]) ||
    !isBoundedUniqueStrings(filters["states"], 20, workflowKeyPattern) ||
    !isEnumList(filters["severities"], alertSeverities, 5) ||
    !isEnumList(filters["priorities"], ticketPriorities, 5) ||
    !["all", "assigned_to_me", "my_operator_teams", "unassigned"].includes(
      String(filters["queue"]),
    ) ||
    !isOptionalUuidV7(filters["assignedTeamId"]) ||
    !isOptionalUuidV7(filters["assigneeUserId"]) ||
    !isOptionalUuidV7(filters["claimedBy"]) ||
    (filters["customerVisible"] !== undefined &&
      typeof filters["customerVisible"] !== "boolean") ||
    (filters["search"] !== undefined &&
      !isSavedViewInputText(filters["search"], 240)) ||
    !Array.isArray(filters["custom"]) ||
    filters["custom"].length > 8 ||
    !filters["custom"].every(isSavedTicketViewCustomFilterInput)
  ) {
    return false;
  }

  const pins = new Map<string, number>();
  const filterIdentities = new Set<string>();
  for (const filter of filters["custom"]) {
    const identity = `custom_field:${String(filter["definitionId"])}`;
    if (
      filterIdentities.has(identity) ||
      !registerSavedViewInputPin(pins, "custom_field", filter)
    ) {
      return false;
    }
    filterIdentities.add(identity);
  }
  const identities = new Set<string>();
  let visibleTicket = false;
  for (const column of value["columns"]) {
    if (!isSavedTicketViewColumnInput(column)) return false;
    const identity = savedTicketViewInputIdentity(column);
    if (identity === undefined || identities.has(identity)) return false;
    identities.add(identity);
    const source = column["source"];
    if (
      (source === "custom_field" || source === "sla") &&
      !registerSavedViewInputPin(pins, source, column)
    ) {
      return false;
    }
    visibleTicket ||=
      column["source"] === "core" &&
      column["coreKey"] === "ticket" &&
      column["visible"] === true;
  }
  return (
    visibleTicket &&
    isSavedTicketViewSortInput(value["sort"], pins, value["columns"])
  );
}

function isSavedTicketViewCustomFilterInput(value: unknown): boolean {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, [
      "definitionId",
      "expectedDefinitionVersion",
      "operator",
      "value",
    ]) &&
    typeof value["definitionId"] === "string" &&
    uuidV7Pattern.test(value["definitionId"]) &&
    isResourceVersion(value["expectedDefinitionVersion"]) &&
    value["operator"] === "equal" &&
    isSavedViewScalarInput(value["value"])
  );
}

function isSavedTicketViewColumnInput(
  value: unknown,
): value is Record<string, unknown> {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "coreKey",
      "definitionId",
      "expectedDefinitionVersion",
      "pin",
      "source",
      "visible",
      "width",
    ]) ||
    typeof value["visible"] !== "boolean" ||
    !["none", "start", "end"].includes(String(value["pin"])) ||
    (value["width"] !== undefined &&
      (!Number.isSafeInteger(value["width"]) ||
        Number(value["width"]) < 80 ||
        Number(value["width"]) > 1_200))
  ) {
    return false;
  }
  if (value["source"] === "core") {
    return (
      typeof value["coreKey"] === "string" &&
      savedViewCoreColumns.has(value["coreKey"]) &&
      value["definitionId"] === undefined &&
      value["expectedDefinitionVersion"] === undefined
    );
  }
  return (
    (value["source"] === "custom_field" || value["source"] === "sla") &&
    value["coreKey"] === undefined &&
    typeof value["definitionId"] === "string" &&
    uuidV7Pattern.test(value["definitionId"]) &&
    isResourceVersion(value["expectedDefinitionVersion"])
  );
}

function isSavedTicketViewSortInput(
  value: Record<string, unknown>,
  pins: ReadonlyMap<string, number>,
  columns: readonly unknown[],
): boolean {
  if (
    !hasOnlyKeys(value, [
      "coreKey",
      "definitionId",
      "direction",
      "expectedDefinitionVersion",
      "nulls",
      "source",
    ]) ||
    !["asc", "desc"].includes(String(value["direction"])) ||
    !["first", "last"].includes(String(value["nulls"]))
  ) {
    return false;
  }
  if (value["source"] === "core") {
    return (
      typeof value["coreKey"] === "string" &&
      savedViewCoreSorts.has(value["coreKey"]) &&
      value["definitionId"] === undefined &&
      value["expectedDefinitionVersion"] === undefined &&
      value["nulls"] === "last" &&
      (value["coreKey"] !== "oldest_unclaimed" || value["direction"] === "asc")
    );
  }
  if (
    (value["source"] !== "custom_field" && value["source"] !== "sla") ||
    value["coreKey"] !== undefined ||
    typeof value["definitionId"] !== "string" ||
    !uuidV7Pattern.test(value["definitionId"]) ||
    !isResourceVersion(value["expectedDefinitionVersion"]) ||
    pins.get(`${value["source"]}:${value["definitionId"]}`) !==
      value["expectedDefinitionVersion"]
  ) {
    return false;
  }
  return columns.some(
    (column) =>
      isRecord(column) &&
      column["source"] === value["source"] &&
      column["definitionId"] === value["definitionId"] &&
      column["expectedDefinitionVersion"] ===
        value["expectedDefinitionVersion"],
  );
}

function savedTicketViewInputIdentity(
  value: Record<string, unknown>,
): string | undefined {
  return value["source"] === "core" && typeof value["coreKey"] === "string"
    ? `core:${value["coreKey"]}`
    : (value["source"] === "custom_field" || value["source"] === "sla") &&
        typeof value["definitionId"] === "string"
      ? `${value["source"]}:${value["definitionId"]}`
      : undefined;
}

function registerSavedViewInputPin(
  pins: Map<string, number>,
  source: "custom_field" | "sla",
  value: Record<string, unknown>,
): boolean {
  if (
    typeof value["definitionId"] !== "string" ||
    !isResourceVersion(value["expectedDefinitionVersion"])
  ) {
    return false;
  }
  const identity = `${source}:${value["definitionId"]}`;
  const current = pins.get(identity);
  if (current !== undefined && current !== value["expectedDefinitionVersion"]) {
    return false;
  }
  pins.set(identity, value["expectedDefinitionVersion"]);
  return true;
}

function isSavedViewScalarInput(value: unknown): boolean {
  return (
    typeof value === "boolean" ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))) ||
    (typeof value === "string" && Array.from(value).length <= 10_000)
  );
}

function isSavedViewInputText(
  value: unknown,
  maximumBytes: number,
): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    !hasGoTrimSpaceAtEdge(value) &&
    new TextEncoder().encode(value).byteLength <= maximumBytes &&
    !hasControlCharacters(value)
  );
}

function isSavedViewExpectedRevision(value: unknown): value is number {
  return isResourceVersion(value) && value <= 2_147_483_646;
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const catalog = new Set(allowed);
  return Object.keys(value).every((key) => catalog.has(key));
}

function isSavedTicketViewSpec(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
): value is SavedTicketView["spec"] {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["columns", "filters", "sort"]) ||
    !isRecord(value["filters"]) ||
    !isRecord(value["sort"]) ||
    !Array.isArray(value["columns"]) ||
    value["columns"].length < 1 ||
    value["columns"].length > 64
  ) {
    return false;
  }
  const filters = value["filters"];
  if (
    !hasOnlyKeys(filters, [
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
    ]) ||
    !isBoundedUniqueStrings(filters["states"], 20, workflowKeyPattern) ||
    !isEnumList(filters["severities"], alertSeverities, 5) ||
    !isEnumList(filters["priorities"], ticketPriorities, 5) ||
    !["all", "assigned_to_me", "my_operator_teams", "unassigned"].includes(
      String(filters["queue"]),
    ) ||
    !isOptionalUuidV7(filters["assignedTeamId"]) ||
    !isOptionalUuidV7(filters["assigneeUserId"]) ||
    !isOptionalUuidV7(filters["claimedBy"]) ||
    (filters["customerVisible"] !== undefined &&
      typeof filters["customerVisible"] !== "boolean") ||
    (filters["search"] !== undefined &&
      !isSavedViewInputText(filters["search"], 240)) ||
    !Array.isArray(filters["custom"]) ||
    filters["custom"].length > 8 ||
    !filters["custom"].every((filter) =>
      isSavedTicketViewCustomFilter(filter, tenantId, kind),
    )
  ) {
    return false;
  }
  const definitionPins = new Map<string, Record<string, unknown>>();
  const definitionKeys = new Map<string, Record<string, unknown>>();
  const filterIdentities = new Set<string>();
  for (const filter of filters["custom"]) {
    const definition = filter["definition"];
    if (!isRecord(definition)) return false;
    const identity = `custom_field:${String(definition["id"])}`;
    if (
      filterIdentities.has(identity) ||
      !registerSavedViewDefinitionPin(
        definitionPins,
        definitionKeys,
        "custom_field",
        definition,
      )
    ) {
      return false;
    }
    filterIdentities.add(identity);
  }
  const columns = value["columns"];
  if (
    !columns.every((column) =>
      isSavedTicketViewColumn(column, tenantId, kind),
    ) ||
    !columns.some(
      (column) =>
        isRecord(column) &&
        column["source"] === "core" &&
        column["coreKey"] === "ticket" &&
        column["visible"] === true,
    )
  ) {
    return false;
  }
  const identities = columns.map(savedTicketViewColumnIdentity);
  if (
    identities.includes(undefined) ||
    new Set(identities).size !== identities.length
  ) {
    return false;
  }
  for (const column of columns) {
    if (
      isRecord(column) &&
      (column["source"] === "custom_field" || column["source"] === "sla") &&
      (!isRecord(column["definition"]) ||
        !registerSavedViewDefinitionPin(
          definitionPins,
          definitionKeys,
          column["source"],
          column["definition"],
        ))
    ) {
      return false;
    }
  }
  return isSavedTicketViewSort(value["sort"], tenantId, kind, columns);
}

const savedViewCoreColumns = new Set([
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
const savedViewCoreSorts = new Set([
  "updated_at",
  "created_at",
  "priority",
  "oldest_unclaimed",
]);
const savedViewScalarTypes = new Set([
  "short_text",
  "long_text",
  "integer",
  "decimal",
  "boolean",
  "date",
  "datetime",
  "duration",
  "single_select",
  "url",
  "email",
  "ip",
  "cidr",
  "user",
  "operator_team",
  "customer_contact",
  "asset_reference",
  "ioc_reference",
]);
const savedViewNumericScalarTypes = new Set(["integer", "decimal", "duration"]);

function isSavedTicketViewColumn(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
): boolean {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "coreKey",
      "definition",
      "pin",
      "source",
      "visible",
      "width",
    ]) ||
    typeof value["visible"] !== "boolean" ||
    !["none", "start", "end"].includes(String(value["pin"])) ||
    !Number.isSafeInteger(value["width"]) ||
    Number(value["width"]) < 0 ||
    Number(value["width"]) > 1200 ||
    (Number(value["width"]) > 0 && Number(value["width"]) < 80)
  ) {
    return false;
  }
  if (value["source"] === "core") {
    return (
      typeof value["coreKey"] === "string" &&
      savedViewCoreColumns.has(value["coreKey"]) &&
      value["definition"] === undefined
    );
  }
  return (
    (value["source"] === "custom_field" || value["source"] === "sla") &&
    value["coreKey"] === undefined &&
    isSavedViewDefinitionPin(value["definition"], tenantId, kind)
  );
}

function savedTicketViewColumnIdentity(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  if (value["source"] === "core" && typeof value["coreKey"] === "string") {
    return `core:${value["coreKey"]}`;
  }
  const definition = value["definition"];
  return isRecord(definition) && typeof definition["id"] === "string"
    ? `${String(value["source"])}:${definition["id"]}`
    : undefined;
}

function isSavedTicketViewSort(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
  columns: unknown[],
): boolean {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "coreKey",
      "definition",
      "direction",
      "nulls",
      "source",
    ]) ||
    !["asc", "desc"].includes(String(value["direction"])) ||
    !["first", "last"].includes(String(value["nulls"]))
  ) {
    return false;
  }
  if (value["source"] === "core") {
    return (
      typeof value["coreKey"] === "string" &&
      savedViewCoreSorts.has(value["coreKey"]) &&
      value["definition"] === undefined &&
      value["nulls"] === "last" &&
      (value["coreKey"] !== "oldest_unclaimed" || value["direction"] === "asc")
    );
  }
  if (
    (value["source"] !== "custom_field" && value["source"] !== "sla") ||
    value["coreKey"] !== undefined ||
    !isSavedViewDefinitionPin(value["definition"], tenantId, kind)
  ) {
    return false;
  }
  const identity = savedTicketViewColumnIdentity(value);
  return columns.some(
    (column) =>
      savedTicketViewColumnIdentity(column) === identity &&
      isRecord(column) &&
      isRecord(column["definition"]) &&
      isRecord(value["definition"]) &&
      sameSavedViewDefinitionPin(column["definition"], value["definition"]),
  );
}

function isSavedTicketViewCustomFilter(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, ["dataType", "definition", "operator", "value"]) &&
    isSavedViewDefinitionPin(value["definition"], tenantId, kind) &&
    typeof value["dataType"] === "string" &&
    savedViewScalarTypes.has(value["dataType"]) &&
    value["operator"] === "equal" &&
    isCanonicalSavedViewResponseScalar(value["value"], value["dataType"])
  );
}

function isCanonicalSavedViewResponseScalar(
  value: unknown,
  dataType: string,
): boolean {
  if (dataType === "boolean") return typeof value === "boolean";
  if (savedViewNumericScalarTypes.has(dataType)) {
    if (typeof value !== "string" || value.length === 0 || value.length > 256) {
      return false;
    }
    if (dataType === "decimal") {
      return (
        value !== "-0" && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/u.test(value)
      );
    }
    if (!/^-?(?:0|[1-9][0-9]*)$/u.test(value) || value === "-0") return false;
    try {
      const parsed = BigInt(value);
      return (
        parsed >=
          (dataType === "duration" ? 0n : -9_223_372_036_854_775_808n) &&
        parsed <= 9_223_372_036_854_775_807n
      );
    } catch {
      return false;
    }
  }
  return typeof value === "string" && Array.from(value).length <= 10_000;
}

function isSavedViewDefinitionPin(
  value: unknown,
  tenantId: string,
  kind: TicketKind,
): boolean {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, [
      "id",
      "key",
      "kind",
      "sha256",
      "tenantId",
      "version",
    ]) &&
    uuidV7Pattern.test(String(value["id"])) &&
    value["tenantId"] === tenantId &&
    value["kind"] === kind &&
    typeof value["key"] === "string" &&
    customFieldKeyPattern.test(value["key"]) &&
    isResourceVersion(value["version"]) &&
    typeof value["sha256"] === "string" &&
    savedViewDigestPattern.test(value["sha256"])
  );
}

function registerSavedViewDefinitionPin(
  pins: Map<string, Record<string, unknown>>,
  keys: Map<string, Record<string, unknown>>,
  source: "custom_field" | "sla",
  pin: Record<string, unknown>,
): boolean {
  const identity = `${source}:${String(pin["id"])}`;
  const stableKey = `${source}:${String(pin["key"])}`;
  const byIdentity = pins.get(identity);
  const byKey = keys.get(stableKey);
  if (
    (byIdentity !== undefined &&
      !sameSavedViewDefinitionPin(byIdentity, pin)) ||
    (byKey !== undefined && !sameSavedViewDefinitionPin(byKey, pin))
  ) {
    return false;
  }
  pins.set(identity, pin);
  keys.set(stableKey, pin);
  return true;
}

function sameSavedViewDefinitionPin(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  return (
    left["id"] === right["id"] &&
    left["tenantId"] === right["tenantId"] &&
    left["kind"] === right["kind"] &&
    left["key"] === right["key"] &&
    left["version"] === right["version"] &&
    left["sha256"] === right["sha256"]
  );
}

function cloneSavedTicketViewSpec(
  value: SavedTicketView["spec"],
): SavedTicketView["spec"] {
  return {
    filters: {
      states: [...value.filters.states],
      severities: [...value.filters.severities],
      priorities: [...value.filters.priorities],
      queue: value.filters.queue,
      custom: value.filters.custom.map((filter) => ({
        definition: cloneSavedViewDefinitionPin(filter.definition),
        dataType: filter.dataType,
        operator: "equal",
        value: filter.value,
      })),
      ...(value.filters.assignedTeamId
        ? { assignedTeamId: value.filters.assignedTeamId }
        : {}),
      ...(value.filters.assigneeUserId
        ? { assigneeUserId: value.filters.assigneeUserId }
        : {}),
      ...(value.filters.claimedBy
        ? { claimedBy: value.filters.claimedBy }
        : {}),
      ...(value.filters.customerVisible === undefined
        ? {}
        : { customerVisible: value.filters.customerVisible }),
      ...(value.filters.search ? { search: value.filters.search } : {}),
    },
    sort:
      value.sort.source === "core"
        ? {
            source: "core",
            coreKey: value.sort.coreKey!,
            direction: value.sort.direction,
            nulls: "last",
          }
        : {
            source: value.sort.source,
            definition: cloneSavedViewDefinitionPin(value.sort.definition!),
            direction: value.sort.direction,
            nulls: value.sort.nulls,
          },
    columns: value.columns.map((column) =>
      column.source === "core"
        ? {
            source: "core",
            coreKey: column.coreKey!,
            width: column.width,
            visible: column.visible,
            pin: column.pin,
          }
        : {
            source: column.source,
            definition: cloneSavedViewDefinitionPin(column.definition!),
            width: column.width,
            visible: column.visible,
            pin: column.pin,
          },
    ),
  };
}

function cloneSavedViewDefinitionPin(
  value: SavedTicketView["spec"]["filters"]["custom"][number]["definition"],
): typeof value {
  return {
    id: value.id,
    tenantId: value.tenantId,
    kind: value.kind,
    key: value.key,
    version: value.version,
    sha256: value.sha256,
  };
}

function requireSavedViewMutationContext(
  csrfToken: string,
  idempotencyKey: string,
  tenantId: string,
): void {
  if (
    !uuidV7Pattern.test(tenantId) ||
    csrfToken.trim() === "" ||
    csrfToken.length > 4096 ||
    csrfToken.includes(",") ||
    !idempotencyKeyPattern.test(idempotencyKey)
  ) {
    throw projectionMismatch(
      "Saved-view request integrity context is unavailable.",
    );
  }
}

function requireTicketMutationContext(
  csrfToken: string,
  etag: string,
  idempotencyKey: string,
  resourceId: string,
  tenantId: string,
  expectedVersion: number,
): void {
  const match = strongEntityTagPattern.exec(etag);
  if (
    !uuidV7Pattern.test(tenantId) ||
    !uuidV7Pattern.test(resourceId) ||
    csrfToken.trim() === "" ||
    csrfToken.length > 4096 ||
    csrfToken.includes(",") ||
    !idempotencyKeyPattern.test(idempotencyKey) ||
    !isResourceVersion(expectedVersion) ||
    match === null ||
    Number(match[1]) !== expectedVersion
  ) {
    throw projectionMismatch(
      "Ticket mutation integrity context is unavailable.",
    );
  }
}

function canonicalSavedViewId(value: string | undefined): string | undefined {
  return value !== undefined && uuidV7Pattern.test(value) ? value : undefined;
}

function requireCanonicalSavedViewId(value: string): void {
  if (!uuidV7Pattern.test(value)) {
    throw projectionMismatch("A canonical saved-view identifier is required.");
  }
}

function requireSavedViewEtag(response: Response | undefined): string {
  const value = response?.headers.get("ETag");
  if (value === null || value === undefined) throw projectionMismatch();
  requireSavedViewEtagValue(value);
  return value;
}

function requireSavedViewEtagValue(value: string): void {
  if (!savedViewEntityTagPattern.test(value)) {
    throw projectionMismatch("A current saved-view validator is required.");
  }
}

function isBoundedDisplayText(
  value: unknown,
  maximum: number,
): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    Array.from(value).length <= maximum &&
    !hasControlCharacters(value)
  );
}

function isCanonicalInstant(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 20 &&
    value.length <= 35 &&
    value.endsWith("Z") &&
    !Number.isNaN(Date.parse(value))
  );
}

function isOptionalUuidV7(value: unknown): boolean {
  return (
    value === undefined ||
    (typeof value === "string" && uuidV7Pattern.test(value))
  );
}

function isBoundedUniqueStrings(
  value: unknown,
  maximum: number,
  pattern: RegExp,
): boolean {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && pattern.test(item))
  );
}

function isEnumList(
  value: unknown,
  catalog: ReadonlySet<string>,
  maximum: number,
): boolean {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    new Set(value).size === value.length &&
    value.every((item) => typeof item === "string" && catalog.has(item))
  );
}

function isTicketDynamicScalar(value: unknown): value is string | boolean {
  return (
    typeof value === "boolean" ||
    (typeof value === "string" && Array.from(value).length <= 65_536)
  );
}

function claimTicketResult(
  result: GeneratedResult<unknown>,
  kind: TicketKind,
): GeneratedResult<unknown> {
  if (result.data === undefined) return result;
  if (!isRecord(result.data)) throw projectionMismatch();
  const ticket = result.data[kind];
  const winner = result.data["winner"];
  if (
    !isRecord(ticket) ||
    !isRecord(winner) ||
    ticket["version"] !== winner["version"] ||
    typeof winner["claimedBy"] !== "string" ||
    typeof winner["claimedAt"] !== "string"
  ) {
    throw projectionMismatch();
  }
  return { ...result, data: ticket };
}

function unwrapVersionedTicket(
  result: GeneratedResult<unknown>,
  kind: TicketKind,
  tenantId: string,
  resourceId?: string,
): VersionedTicket {
  const value = projectTicket(kind, tenantId, resourceId, unwrap(result));
  return {
    etag: requireVersionEtag(result.response, value.version),
    value,
  };
}

function unwrapOperatorTicket(
  result: GeneratedResult<unknown>,
  kind: TicketKind,
  tenantId: string,
  resourceId?: string,
): VersionedTicket<OperatorTicketProjection> {
  const versioned = unwrapVersionedTicket(result, kind, tenantId, resourceId);
  if (versioned.value.projection !== "operator") {
    throw projectionMismatch();
  }
  return { etag: versioned.etag, value: versioned.value };
}

function projectTicket(
  kind: TicketKind,
  tenantId: string,
  resourceId: string | undefined,
  value: unknown,
): TicketProjection {
  if (
    !isRecord(value) ||
    value["tenantId"] !== tenantId ||
    (resourceId !== undefined && value["id"] !== resourceId) ||
    typeof value["id"] !== "string" ||
    !isResourceVersion(value["version"]) ||
    !isRecord(value["workflow"]) ||
    value["workflow"]["kind"] !== kind
  ) {
    throw projectionMismatch();
  }
  if (value["projection"] === "operator") {
    if (!isOperatorTicketProjection(value, kind)) throw projectionMismatch();
    return value;
  }
  if (
    value["projection"] !== "customer" ||
    value["visibility"] !== "customer" ||
    value["customerVisible"] !== true
  ) {
    throw projectionMismatch();
  }
  if (kind === "alert") {
    if (!isCustomerAlertProjection(value)) throw projectionMismatch();
    return projectCustomerAlert(value);
  }
  if (!isCustomerCaseProjection(value)) throw projectionMismatch();
  return projectCustomerCase(value);
}

function projectCustomerAlert(
  source: Extract<AlertProjection, { projection: "customer" }>,
): AlertProjection {
  return {
    projection: "customer",
    id: source.id,
    tenantId: source.tenantId,
    alertNumber: source.alertNumber,
    title: source.title,
    description: source.description,
    workflow: { ...source.workflow },
    severity: source.severity,
    priority: source.priority,
    category: source.category,
    detectedAt: source.detectedAt,
    receivedAt: source.receivedAt,
    visibility: "customer",
    customerVisible: true,
    tags: [...source.tags],
    customFields: { ...source.customFields },
    version: source.version,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  };
}

function projectCustomerCase(
  source: Extract<CaseProjection, { projection: "customer" }>,
): CaseProjection {
  return {
    projection: "customer",
    id: source.id,
    tenantId: source.tenantId,
    caseNumber: source.caseNumber,
    title: source.title,
    summary: source.summary,
    description: source.description,
    workflow: { ...source.workflow },
    severity: source.severity,
    priority: source.priority,
    category: source.category,
    detectionTime: source.detectionTime,
    openedAt: source.openedAt,
    visibility: "customer",
    customerVisible: true,
    tags: [...source.tags],
    customFields: { ...source.customFields },
    version: source.version,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  };
}

const operatorCommentKeys = [
  "projection",
  "id",
  "tenantId",
  "resourceKind",
  "resourceId",
  "origin",
  "visibility",
  "bodyMarkdown",
  "bodyHtml",
  "author",
  "attachments",
  "mentions",
  "revision",
  "canEdit",
  "editableUntil",
  "createdAt",
  "updatedAt",
] as const;
const customerCommentKeys = operatorCommentKeys.filter(
  (key) => key !== "mentions",
);
const rawHtmlPattern = /<\/?[A-Za-z]/u;

function requireCommentCoordinates(
  kind: TicketKind,
  tenantId: string,
  resourceId: string,
  commentId?: string,
): void {
  if (
    (kind !== "alert" && kind !== "case") ||
    !uuidV7Pattern.test(tenantId) ||
    !uuidV7Pattern.test(resourceId) ||
    (commentId !== undefined && !uuidV7Pattern.test(commentId))
  ) {
    throw projectionMismatch(
      "Canonical UUIDv7 comment coordinates are required.",
    );
  }
}

function requireCsrfToken(csrfToken: string): void {
  if (
    csrfToken.trim() === "" ||
    csrfToken.length > 4096 ||
    csrfToken.includes(",") ||
    hasControlCharacters(csrfToken)
  ) {
    throw projectionMismatch(
      "Comment request integrity context is unavailable.",
    );
  }
}

function requireCommentMutationHeaders(
  csrfToken: string,
  idempotencyKey: string,
): void {
  requireCsrfToken(csrfToken);
  if (!idempotencyKeyPattern.test(idempotencyKey)) {
    throw projectionMismatch(
      "A canonical comment idempotency key is required.",
    );
  }
}

function requireCommentCreateRequest(value: CommentCreateRequest): void {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "bodyMarkdown",
      "visibility",
      "attachmentIds",
      "mentionedMembershipIds",
    ]) ||
    !isSafeCommentMarkdown(value["bodyMarkdown"]) ||
    !isCommentVisibility(value["visibility"]) ||
    !isCanonicalCommentIds(value["attachmentIds"], 20) ||
    !isCanonicalCommentIds(value["mentionedMembershipIds"], 50)
  ) {
    throw projectionMismatch(
      "The comment draft was not canonical and bounded.",
    );
  }
}

function requireCommentEditRequest(value: CommentEditRequest): void {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "bodyMarkdown",
      "reason",
      "attachmentIds",
      "mentionedMembershipIds",
    ]) ||
    !isSafeCommentMarkdown(value["bodyMarkdown"]) ||
    !isCommentEditReason(value["reason"]) ||
    !isCanonicalCommentIds(value["attachmentIds"], 20) ||
    !isCanonicalCommentIds(value["mentionedMembershipIds"], 50)
  ) {
    throw projectionMismatch("The comment edit was not canonical and bounded.");
  }
}

function requireCommentEtag(value: string): number {
  const match = commentEntityTagPattern.exec(value);
  const revision = match ? Number(match[1]) : 0;
  if (!isResourceVersion(revision)) {
    throw projectionMismatch("An exact current comment revision is required.");
  }
  return revision;
}

function requireCommentResponseEtag(
  response: Response | undefined,
  revision: number,
): string {
  const value = response?.headers.get("ETag");
  if (
    value === null ||
    value === undefined ||
    requireCommentEtag(value) !== revision
  ) {
    throw projectionMismatch(
      "The comment response ETag did not match its revision.",
    );
  }
  return value;
}

function requireReplayHeader(response: Response | undefined): boolean {
  const value = response?.headers.get("X-Idempotent-Replay");
  if (value !== "true" && value !== "false") {
    throw projectionMismatch(
      "The comment replay receipt was missing or invalid.",
    );
  }
  return value === "true";
}

function isSafeCommentMarkdown(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !hasGoTrimSpaceAtEdge(value) &&
    Array.from(value).length <= 20_000 &&
    !hasForbiddenCommentMarkdownCharacters(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isCommentEditReason(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim() !== "" &&
    Array.from(value).length <= 500 &&
    !hasControlCharacters(value) &&
    !hasBidiControlCharacters(value) &&
    !rawHtmlPattern.test(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isBoundedCommentSearch(value: string): boolean {
  return (
    value.trim() !== "" &&
    Array.from(value).length <= 100 &&
    !hasControlCharacters(value) &&
    !hasBidiControlCharacters(value) &&
    !/[<>]/u.test(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isCanonicalCommentIds(value: unknown, maximum: number): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value) || value.length > maximum) return false;
  let previous: string | undefined;
  for (const id of value) {
    if (
      typeof id !== "string" ||
      !uuidV7Pattern.test(id) ||
      (previous !== undefined && compareUtf8Bytewise(previous, id) >= 0)
    ) {
      return false;
    }
    previous = id;
  }
  return true;
}

function projectOperatorCommentPreview(
  value: unknown,
  expectedVisibility: CommentCreateRequest["visibility"],
): TicketCommentPreview {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "visibility",
      "bodyMarkdown",
      "bodyHtml",
      "attachments",
      "mentions",
    ]) ||
    value["visibility"] !== expectedVisibility ||
    !isSafeCommentMarkdown(value["bodyMarkdown"]) ||
    typeof value["bodyHtml"] !== "string" ||
    Array.from(value["bodyHtml"]).length > 100_000 ||
    !isOperatorCommentAttachments(value["attachments"]) ||
    !isOperatorCommentMentions(value["mentions"]) ||
    (expectedVisibility === "public" &&
      value["attachments"].some(
        (attachment) => attachment.visibility !== "public",
      ))
  ) {
    throw projectionMismatch("The comment preview was not safe to display.");
  }
  return {
    visibility: expectedVisibility,
    bodyMarkdown: value["bodyMarkdown"],
    attachments: value["attachments"].map((attachment) => ({ ...attachment })),
    mentions: value["mentions"].map((mention) => ({ ...mention })),
  };
}

function projectCommentMentionCandidates(
  value: unknown,
): CommentMentionCandidate[] {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["items"]) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100
  ) {
    throw projectionMismatch("The mention candidate projection was invalid.");
  }
  const result: CommentMentionCandidate[] = [];
  const membershipIds = new Set<string>();
  let previous: CommentMentionCandidate | undefined;
  for (const candidate of value["items"]) {
    if (
      !isCommentMentionCandidate(candidate) ||
      membershipIds.has(candidate.membershipId)
    ) {
      throw projectionMismatch("The mention candidate projection was invalid.");
    }
    if (
      previous !== undefined &&
      (compareUtf8Bytewise(previous.displayName, candidate.displayName) > 0 ||
        (previous.displayName === candidate.displayName &&
          compareUtf8Bytewise(previous.membershipId, candidate.membershipId) >=
            0))
    ) {
      throw projectionMismatch(
        "Mention candidates were not in canonical order.",
      );
    }
    membershipIds.add(candidate.membershipId);
    result.push({ ...candidate });
    previous = candidate;
  }
  return result;
}

function projectOperatorCommentRevisionPage(
  value: unknown,
  afterRevision: number | undefined,
): CommentRevisionPage {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["items", "nextAfterRevision"]) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextAfterRevision"] !== undefined &&
      !isResourceVersion(value["nextAfterRevision"]))
  ) {
    throw projectionMismatch("The comment revision history was invalid.");
  }
  const items: TicketCommentRevision[] = [];
  let previous = afterRevision;
  for (const revision of value["items"]) {
    if (
      !isOperatorCommentRevision(revision) ||
      (previous !== undefined && revision.revision >= previous)
    ) {
      throw projectionMismatch(
        "Comment revisions were not strictly newest-first.",
      );
    }
    items.push({
      projection: "operator",
      revision: revision.revision,
      bodyMarkdown: revision.bodyMarkdown,
      attachments: revision.attachments.map((attachment) => ({
        ...attachment,
      })),
      mentions: revision.mentions.map((mention) => ({ ...mention })),
      reason: revision.reason,
      editedAt: revision.editedAt,
    });
    previous = revision.revision;
  }
  if (
    value["nextAfterRevision"] !== undefined &&
    (items.length === 0 ||
      value["nextAfterRevision"] !== items.at(-1)?.revision)
  ) {
    throw projectionMismatch("The comment history cursor was not canonical.");
  }
  return {
    items,
    ...(value["nextAfterRevision"] === undefined
      ? {}
      : { nextAfterRevision: value["nextAfterRevision"] }),
  };
}

function projectOperatorCommentPage(
  value: unknown,
  kind: TicketKind,
  tenantId: string,
  resourceId: string,
): CursorPage<Extract<TicketComment, { projection: "operator" }>> {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["items", "nextCursor"]) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        !uuidV7Pattern.test(value["nextCursor"])))
  ) {
    throw projectionMismatch("The operator comment page was invalid.");
  }
  const ids = new Set<string>();
  const items = value["items"].map((item) => {
    const comment = projectComment(kind, tenantId, resourceId, item);
    if (comment.projection !== "operator" || ids.has(comment.id)) {
      throw projectionMismatch("The operator comment page was invalid.");
    }
    ids.add(comment.id);
    return comment;
  });
  return {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function projectComment(
  kind: TicketKind,
  tenantId: string,
  resourceId: string,
  value: unknown,
): TicketComment {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(
      value,
      value["projection"] === "operator"
        ? operatorCommentKeys
        : customerCommentKeys,
    ) ||
    value["tenantId"] !== tenantId ||
    value["resourceId"] !== resourceId ||
    value["resourceKind"] !== kind ||
    typeof value["id"] !== "string" ||
    !uuidV7Pattern.test(value["id"]) ||
    !isCommentOrigin(value["origin"]) ||
    !isSafeCommentMarkdown(value["bodyMarkdown"]) ||
    typeof value["bodyHtml"] !== "string" ||
    Array.from(value["bodyHtml"]).length > 100_000 ||
    !isResourceVersion(value["revision"]) ||
    typeof value["canEdit"] !== "boolean" ||
    (value["canEdit"] &&
      ((value["projection"] === "operator" && value["origin"] !== "api") ||
        (value["projection"] === "customer" &&
          value["origin"] !== "customer_portal"))) ||
    !isCanonicalInstant(value["editableUntil"]) ||
    !isCanonicalInstant(value["createdAt"]) ||
    !isCanonicalInstant(value["updatedAt"]) ||
    !hasCanonicalCommentTimeline(
      value["createdAt"],
      value["updatedAt"],
      value["editableUntil"],
    )
  ) {
    throw projectionMismatch();
  }
  if (value["projection"] === "customer") {
    if (
      value["visibility"] !== "public" ||
      !isCustomerCommentAuthor(value["author"]) ||
      !isCommentOriginAudienceCoherent(
        value["origin"],
        value["author"].audience,
      ) ||
      !isCustomerCommentAttachments(value["attachments"]) ||
      (value["canEdit"] && value["author"].audience !== "customer")
    ) {
      throw projectionMismatch();
    }
    return {
      projection: "customer",
      id: value["id"],
      tenantId,
      resourceKind: kind,
      resourceId,
      origin: value["origin"],
      visibility: "public",
      bodyMarkdown: value["bodyMarkdown"],
      author: value["author"],
      attachments: value["attachments"],
      revision: value["revision"],
      canEdit: value["canEdit"],
      editableUntil: value["editableUntil"],
      createdAt: value["createdAt"],
      updatedAt: value["updatedAt"],
    };
  }
  if (
    value["projection"] !== "operator" ||
    !isCommentVisibility(value["visibility"]) ||
    !isOperatorCommentAuthor(value["author"]) ||
    !isCommentOriginAudienceCoherent(
      value["origin"],
      value["author"].audience,
    ) ||
    !isOperatorCommentAttachments(value["attachments"]) ||
    !isOperatorCommentMentions(value["mentions"]) ||
    (value["canEdit"] && value["author"].audience !== "operator") ||
    (value["visibility"] === "public" &&
      value["attachments"].some(
        (attachment) => attachment.visibility !== "public",
      ))
  ) {
    throw projectionMismatch();
  }
  return {
    projection: "operator",
    id: value["id"],
    tenantId,
    resourceKind: kind,
    resourceId,
    origin: value["origin"],
    visibility: value["visibility"],
    bodyMarkdown: value["bodyMarkdown"],
    author: value["author"],
    attachments: value["attachments"],
    mentions: value["mentions"],
    revision: value["revision"],
    canEdit: value["canEdit"],
    editableUntil: value["editableUntil"],
    createdAt: value["createdAt"],
    updatedAt: value["updatedAt"],
  };
}

function projectActivity(
  kind: TicketKind,
  tenantId: string,
  resourceId: string,
  value: unknown,
): ActivityProjection {
  if (
    !isRecord(value) ||
    value["tenantId"] !== tenantId ||
    value["resourceId"] !== resourceId ||
    value["resourceKind"] !== kind ||
    typeof value["id"] !== "string" ||
    typeof value["summary"] !== "string" ||
    typeof value["occurredAt"] !== "string" ||
    !isCommentAuthor(value["actor"])
  ) {
    throw projectionMismatch();
  }
  const actor = value["actor"];
  if (value["projection"] === "customer") {
    if (!isCustomerActivityKind(value["kind"])) {
      throw projectionMismatch();
    }
    return {
      projection: "customer",
      id: value["id"],
      tenantId,
      resourceKind: kind,
      resourceId,
      kind: value["kind"],
      summary: value["summary"],
      actor: {
        displayName: actor["displayName"],
        origin: actor["origin"],
      },
      occurredAt: value["occurredAt"],
    };
  }
  if (
    value["projection"] !== "operator" ||
    !isOperatorActivityKind(value["kind"]) ||
    (value["details"] !== undefined &&
      !isCustomFieldValues(value["details"], 25))
  ) {
    throw projectionMismatch();
  }
  const operatorActor = projectOperatorActivityActor(actor);
  return {
    projection: "operator",
    id: value["id"],
    tenantId,
    resourceKind: kind,
    resourceId,
    kind: value["kind"],
    summary: value["summary"],
    actor: operatorActor,
    ...(value["details"] === undefined ? {} : { details: value["details"] }),
    occurredAt: value["occurredAt"],
  };
}

function projectGlobalActivityPage(
  value: unknown,
  kind: TicketKind,
  tenantId: string,
): CursorPage<Extract<ActivityProjection, { projection: "operator" }>> {
  if (
    !isRecord(value) ||
    !hasExactObjectKeys(value, ["items", "nextCursor"]) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        !uuidV7Pattern.test(value["nextCursor"])))
  ) {
    throw projectionMismatch();
  }
  const seen = new Set<string>();
  let previousId: string | undefined;
  const items = value["items"].map((item) => {
    if (
      !isRecord(item) ||
      item["projection"] !== "operator" ||
      item["tenantId"] !== tenantId ||
      item["resourceKind"] !== kind ||
      typeof item["resourceId"] !== "string" ||
      !uuidV7Pattern.test(item["resourceId"]) ||
      typeof item["id"] !== "string" ||
      !uuidV7Pattern.test(item["id"]) ||
      !hasExactObjectKeys(item, [
        "actor",
        "details",
        "id",
        "kind",
        "occurredAt",
        "projection",
        "resourceId",
        "resourceKind",
        "summary",
        "tenantId",
      ])
    ) {
      throw projectionMismatch();
    }
    if (
      seen.has(item["id"]) ||
      (previousId !== undefined && previousId <= item["id"])
    ) {
      throw projectionMismatch();
    }
    seen.add(item["id"]);
    previousId = item["id"];
    const projected = projectActivity(kind, tenantId, item["resourceId"], item);
    if (projected.projection !== "operator") throw projectionMismatch();
    return projected;
  });
  if (
    typeof value["nextCursor"] === "string" &&
    (items.length === 0 || value["nextCursor"] !== items.at(-1)?.id)
  ) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function projectOperatorActivityActor(
  value: unknown,
): OperatorActivityActorProjection {
  if (!isCommentAuthor(value)) throw projectionMismatch();
  if (
    value["principalType"] === undefined &&
    typeof value["membershipId"] === "string" &&
    value["serviceAccountId"] === undefined
  ) {
    return {
      displayName: value["displayName"],
      membershipId: value["membershipId"],
      origin: value["origin"],
    };
  }
  if (
    value["principalType"] === "service_account" &&
    value["origin"] === "operator" &&
    value["membershipId"] === undefined &&
    typeof value["serviceAccountId"] === "string"
  ) {
    return {
      displayName: value["displayName"],
      origin: "operator",
      principalType: "service_account",
      serviceAccountId: value["serviceAccountId"],
    };
  }
  if (
    value["principalType"] === "system" &&
    value["origin"] === "operator" &&
    value["membershipId"] === undefined &&
    value["serviceAccountId"] === undefined
  ) {
    return {
      displayName: value["displayName"],
      origin: "operator",
      principalType: "system",
    };
  }
  throw projectionMismatch();
}

function projectLink(
  tenantId: string,
  resourceId: string,
  kind: TicketKind,
  value: unknown,
): AlertCaseLinkView {
  if (
    !isAlertCaseLinkView(value) ||
    value["tenantId"] !== tenantId ||
    (kind === "alert"
      ? value["alertId"] !== resourceId
      : value["caseId"] !== resourceId) ||
    (value["projection"] !== "operator" && value["projection"] !== "customer")
  ) {
    throw projectionMismatch();
  }
  if (value["projection"] === "customer") {
    return {
      projection: "customer",
      id: value["id"],
      tenantId,
      alertId: value["alertId"],
      caseId: value["caseId"],
      linkedAt: value["linkedAt"],
      relationType: value["relationType"],
    };
  }
  return value;
}

function projectAlertCaseLinkPage(
  value: unknown,
  tenantId: string,
  resourceId: string,
  kind: TicketKind,
): CursorPage<AlertCaseLinkView> {
  if (
    !isRecord(value) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        !uuidV7Pattern.test(value["nextCursor"])))
  ) {
    throw projectionMismatch();
  }
  const items = value["items"].map((item) =>
    projectLink(tenantId, resourceId, kind, item),
  );
  if (hasDuplicateAlertCaseLinks(items)) throw projectionMismatch();
  return {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function hasDuplicateAlertCaseLinks(links: AlertCaseLinkView[]): boolean {
  const ids = new Set<string>();
  const pairs = new Set<string>();
  for (const link of links) {
    const pair = `${link.tenantId}\u0000${link.alertId}\u0000${link.caseId}`;
    if (ids.has(link.id) || pairs.has(pair)) return true;
    ids.add(link.id);
    pairs.add(pair);
  }
  return false;
}

function projectCursorPage<T>(
  value: unknown,
  project: (item: unknown) => T,
): CursorPage<T> {
  if (
    !isRecord(value) ||
    !Array.isArray(value["items"]) ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        value["nextCursor"].length === 0))
  ) {
    throw projectionMismatch();
  }
  return {
    items: value["items"].map(project),
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function projectAlertContactLinkPage(
  value: unknown,
  tenantId: string,
  alertId: string,
): CursorPage<TicketCustomerContactLink> {
  if (
    !isRecord(value) ||
    !Array.isArray(value["items"]) ||
    value["items"].length > 100 ||
    (value["nextCursor"] !== undefined &&
      (typeof value["nextCursor"] !== "string" ||
        value["nextCursor"].length === 0 ||
        value["nextCursor"].length > 512 ||
        !/^[A-Za-z0-9_-]+$/u.test(value["nextCursor"])))
  ) {
    throw projectionMismatch();
  }
  const seenLinks = new Set<string>();
  const items = value["items"].map((item) => {
    const link = projectAlertContactLink(item, tenantId, alertId);
    if (seenLinks.has(link.id)) throw projectionMismatch();
    seenLinks.add(link.id);
    return link;
  });
  return {
    items,
    ...(typeof value["nextCursor"] === "string"
      ? { nextCursor: value["nextCursor"] }
      : {}),
  };
}

function projectAlertContactLink(
  value: unknown,
  tenantId: string,
  alertId: string,
): TicketCustomerContactLink {
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, [
      "contactId",
      "createdAt",
      "escalationProvenance",
      "id",
      "origin",
      "resourceId",
      "resourceKind",
      "role",
      "tenantId",
      "version",
    ]) ||
    typeof value["id"] !== "string" ||
    !uuidPattern.test(value["id"]) ||
    value["tenantId"] !== tenantId ||
    value["resourceKind"] !== "alert" ||
    value["resourceId"] !== alertId ||
    typeof value["contactId"] !== "string" ||
    !uuidPattern.test(value["contactId"]) ||
    !isContactRole(value["role"]) ||
    !isContactOrigin(value["origin"]) ||
    !isResourceVersion(value["version"]) ||
    !isCanonicalInstant(value["createdAt"])
  ) {
    throw projectionMismatch();
  }
  const escalationProvenance = projectAlertContactProvenance(
    value["escalationProvenance"],
    alertId,
  );
  return {
    id: value["id"],
    tenantId,
    resourceKind: "alert",
    resourceId: alertId,
    contactId: value["contactId"],
    role: value["role"],
    origin: value["origin"],
    ...(escalationProvenance === undefined ? {} : { escalationProvenance }),
    version: value["version"],
    createdAt: value["createdAt"],
  };
}

function projectAlertContactProvenance(
  value: unknown,
  alertId: string,
): TicketCustomerContactLink["escalationProvenance"] {
  if (value === undefined) return undefined;
  if (
    !isRecord(value) ||
    !hasOnlyKeys(value, ["sourceAlertId", "sourceAlertVersion"]) ||
    value["sourceAlertId"] !== alertId ||
    !isResourceVersion(value["sourceAlertVersion"])
  ) {
    throw projectionMismatch();
  }
  return {
    sourceAlertId: alertId,
    sourceAlertVersion: value["sourceAlertVersion"],
  };
}

function isContactRole(
  value: unknown,
): value is TicketCustomerContactLink["role"] {
  return value === "primary" || value === "escalation" || value === "watcher";
}

function isContactOrigin(
  value: unknown,
): value is TicketCustomerContactLink["origin"] {
  return value === "manual" || value === "escalation_copy";
}

function requireVersionEtag(
  response: Response | undefined,
  version: number,
): string {
  const etag = response?.headers.get("ETag");
  const match = etag ? strongEntityTagPattern.exec(etag) : null;
  if (!match || Number(match[1]) !== version) {
    throw projectionMismatch(
      "The API did not return the required current ticket version.",
    );
  }
  return etag!;
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw toTicketingApiError(result.error, result.response);
}

function toTicketingApiError(
  value: unknown,
  response?: Response,
): TicketingApiError {
  const problem = isRecord(value) ? value : undefined;
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
  return new TicketingApiError(
    (detail ?? title ?? fallbackForStatus(response?.status)).slice(0, 320),
    response?.status,
    code,
    requestId,
  );
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The ticket request was not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The server denied this ticket operation.";
    case 404:
      return "The requested ticket is not available in this tenant projection.";
    case 409:
      return "This attempt conflicts with current server state.";
    case 412:
      return "This ticket changed on the server. Review the current version before retrying.";
    case 428:
      return "The current ticket version is required for this action.";
    case 503:
      return "A required ticketing dependency is unavailable.";
    default:
      return "The ticket request could not be completed.";
  }
}

function projectionMismatch(
  message = "The ticket projection was not safe to display.",
) {
  return new TicketingApiError(message, undefined, "projection_mismatch");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactObjectKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(value);
  const allowedKeys = new Set(allowed);
  return (
    keys.every((key) => allowedKeys.has(key)) &&
    allowed.every(
      (key) => key === "details" || key === "nextCursor" || key in value,
    )
  );
}

function isOperatorTicketProjection(
  value: Record<string, unknown>,
  kind: TicketKind,
): value is OperatorTicketProjection {
  if (
    value["projection"] !== "operator" ||
    !hasCommonTicketFields(value, kind) ||
    !isTicketAssignment(value["assignment"]) ||
    !isTicketCreator(value["creator"]) ||
    (value["dynamicColumns"] !== undefined &&
      !isTicketDynamicColumns(value["dynamicColumns"])) ||
    (value["availableTransitions"] !== undefined &&
      !isWorkflowActionHints(value["availableTransitions"]))
  ) {
    return false;
  }
  return kind === "alert"
    ? typeof value["alertNumber"] === "string" &&
        typeof value["source"] === "string" &&
        typeof value["sourceType"] === "string" &&
        typeof value["detectedAt"] === "string" &&
        typeof value["receivedAt"] === "string"
    : typeof value["caseNumber"] === "string" &&
        typeof value["summary"] === "string" &&
        typeof value["detectionTime"] === "string" &&
        typeof value["openedAt"] === "string";
}

function isTicketDynamicColumns(value: unknown): boolean {
  if (!Array.isArray(value) || value.length > 64) return false;
  const identities = new Set<string>();
  for (const column of value) {
    if (
      !isRecord(column) ||
      (column["source"] !== "custom_field" && column["source"] !== "sla") ||
      typeof column["definitionId"] !== "string" ||
      !uuidV7Pattern.test(column["definitionId"]) ||
      !isResourceVersion(column["definitionVersion"]) ||
      !isTicketDynamicScalar(column["value"])
    ) {
      return false;
    }
    const identity = `${column["source"]}:${column["definitionId"]}`;
    if (identities.has(identity)) return false;
    identities.add(identity);
    if (
      column["source"] === "sla" &&
      (!isCanonicalInstant(column["materializedAt"]) ||
        (column["styleKey"] !== undefined &&
          (!isBoundedDisplayText(column["styleKey"], 64) ||
            !/^[a-z][a-z0-9_.-]{0,63}$/u.test(column["styleKey"]))))
    ) {
      return false;
    }
    if (
      column["source"] === "custom_field" &&
      (column["materializedAt"] !== undefined ||
        column["styleKey"] !== undefined)
    ) {
      return false;
    }
  }
  return true;
}

function isCustomerAlertProjection(
  value: Record<string, unknown>,
): value is Extract<AlertProjection, { projection: "customer" }> {
  return (
    value["projection"] === "customer" &&
    hasCommonTicketFields(value, "alert") &&
    isRecord(value["workflow"]) &&
    value["workflow"]["customerVisible"] === true &&
    typeof value["alertNumber"] === "string" &&
    typeof value["detectedAt"] === "string" &&
    typeof value["receivedAt"] === "string"
  );
}

function isCustomerCaseProjection(
  value: Record<string, unknown>,
): value is Extract<CaseProjection, { projection: "customer" }> {
  return (
    value["projection"] === "customer" &&
    hasCommonTicketFields(value, "case") &&
    isRecord(value["workflow"]) &&
    value["workflow"]["customerVisible"] === true &&
    typeof value["caseNumber"] === "string" &&
    typeof value["summary"] === "string" &&
    typeof value["detectionTime"] === "string" &&
    typeof value["openedAt"] === "string"
  );
}

function hasCommonTicketFields(
  value: Record<string, unknown>,
  kind: TicketKind,
): boolean {
  const workflow = value["workflow"];
  return (
    typeof value["id"] === "string" &&
    typeof value["tenantId"] === "string" &&
    typeof value["title"] === "string" &&
    typeof value["description"] === "string" &&
    typeof value["category"] === "string" &&
    alertSeverities.has(String(value["severity"])) &&
    ticketPriorities.has(String(value["priority"])) &&
    typeof value["customerVisible"] === "boolean" &&
    ["customer", "internal"].includes(String(value["visibility"])) &&
    isTicketTags(value["tags"]) &&
    isCustomFieldValues(value["customFields"]) &&
    isResourceVersion(value["version"]) &&
    typeof value["createdAt"] === "string" &&
    typeof value["updatedAt"] === "string" &&
    isRecord(workflow) &&
    workflow["kind"] === kind &&
    typeof workflow["workflowId"] === "string" &&
    typeof workflow["stateKey"] === "string" &&
    workflowKeyPattern.test(workflow["stateKey"]) &&
    isResourceVersion(workflow["version"]) &&
    typeof workflow["initial"] === "boolean" &&
    typeof workflow["terminal"] === "boolean" &&
    typeof workflow["customerVisible"] === "boolean"
  );
}

function isTicketAssignment(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return ["assignedTeamId", "assigneeUserId", "claimedAt", "claimedBy"].every(
    (key) => value[key] === null || typeof value[key] === "string",
  );
}

function isTicketCreator(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return value["principalType"] === "human"
    ? typeof value["membershipId"] === "string"
    : value["principalType"] === "service_account" &&
        typeof value["serviceAccountId"] === "string";
}

function isWorkflowActionHints(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= 50 &&
    value.every(
      (hint) =>
        isRecord(hint) &&
        typeof hint["transitionKey"] === "string" &&
        workflowKeyPattern.test(hint["transitionKey"]) &&
        typeof hint["targetStateKey"] === "string" &&
        workflowKeyPattern.test(hint["targetStateKey"]) &&
        typeof hint["commentRequired"] === "boolean" &&
        Array.isArray(hint["requiredCustomFieldKeys"]) &&
        hint["requiredCustomFieldKeys"].length <= 50 &&
        hint["requiredCustomFieldKeys"].every(
          (key) => typeof key === "string" && customFieldKeyPattern.test(key),
        ),
    )
  );
}

function isTicketTags(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= 100 &&
    new Set(value).size === value.length &&
    value.every((tag) => typeof tag === "string" && ticketTagPattern.test(tag))
  );
}

function isCustomFieldValues(
  value: unknown,
  maximum = 100,
): value is SafeCustomFieldValues {
  if (!isRecord(value)) return false;
  const entries = Object.entries(value);
  return (
    entries.length <= maximum &&
    entries.every(
      ([key, field]) =>
        customFieldKeyPattern.test(key) && isCustomFieldValue(field),
    )
  );
}

function isCustomFieldValue(value: unknown): value is SafeCustomFieldValue {
  if (value === null) return true;
  if (["string", "number", "boolean"].includes(typeof value)) return true;
  return (
    Array.isArray(value) &&
    value.length <= 100 &&
    value.every((item) => ["string", "number", "boolean"].includes(typeof item))
  );
}

function isCommentOrigin(value: unknown): value is TicketComment["origin"] {
  return (
    value === "api" ||
    value === "customer_portal" ||
    value === "escalation_copy" ||
    value === "system"
  );
}

function isCommentOriginAudienceCoherent(
  origin: TicketComment["origin"],
  audience: "customer" | "operator",
): boolean {
  if (origin === "escalation_copy") return true;
  return origin === "customer_portal"
    ? audience === "customer"
    : audience === "operator";
}

function isOperatorCommentAuthor(
  value: unknown,
): value is Extract<TicketComment, { projection: "operator" }>["author"] {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, ["membershipId", "displayName", "audience"]) &&
    typeof value["membershipId"] === "string" &&
    uuidV7Pattern.test(value["membershipId"]) &&
    isCanonicalDisplayName(value["displayName"], 200) &&
    (value["audience"] === "operator" || value["audience"] === "customer")
  );
}

function isCustomerCommentAuthor(
  value: unknown,
): value is Extract<TicketComment, { projection: "customer" }>["author"] {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, ["displayName", "audience"]) &&
    isCanonicalDisplayName(value["displayName"], 200) &&
    (value["audience"] === "operator" || value["audience"] === "customer")
  );
}

function isOperatorCommentAttachments(
  value: unknown,
): value is OperatorCommentAttachment[] {
  if (!Array.isArray(value) || value.length > 20) return false;
  let previous: string | undefined;
  for (const attachment of value) {
    if (
      !isRecord(attachment) ||
      !hasOnlyKeys(attachment, [
        "projection",
        "id",
        "originalFilename",
        "visibility",
      ]) ||
      attachment["projection"] !== "operator" ||
      typeof attachment["id"] !== "string" ||
      !uuidV7Pattern.test(attachment["id"]) ||
      !isSafeCommentFilename(attachment["originalFilename"]) ||
      !isCommentVisibility(attachment["visibility"]) ||
      (previous !== undefined &&
        compareUtf8Bytewise(previous, attachment["id"]) >= 0)
    ) {
      return false;
    }
    previous = attachment["id"];
  }
  return true;
}

function isCustomerCommentAttachments(
  value: unknown,
): value is CustomerCommentAttachment[] {
  if (!Array.isArray(value) || value.length > 20) return false;
  let previous: string | undefined;
  for (const attachment of value) {
    if (
      !isRecord(attachment) ||
      !hasOnlyKeys(attachment, ["projection", "id", "originalFilename"]) ||
      attachment["projection"] !== "customer" ||
      typeof attachment["id"] !== "string" ||
      !uuidV7Pattern.test(attachment["id"]) ||
      !isSafeCommentFilename(attachment["originalFilename"]) ||
      (previous !== undefined &&
        compareUtf8Bytewise(previous, attachment["id"]) >= 0)
    ) {
      return false;
    }
    previous = attachment["id"];
  }
  return true;
}

function isOperatorCommentMentions(
  value: unknown,
): value is OperatorCommentMention[] {
  if (!Array.isArray(value) || value.length > 50) return false;
  let previous: string | undefined;
  for (const mention of value) {
    if (
      !isRecord(mention) ||
      !hasOnlyKeys(mention, ["membershipId", "displayName", "audience"]) ||
      typeof mention["membershipId"] !== "string" ||
      !uuidV7Pattern.test(mention["membershipId"]) ||
      !isCanonicalDisplayName(mention["displayName"], 200) ||
      mention["audience"] !== "operator" ||
      (previous !== undefined &&
        compareUtf8Bytewise(previous, mention["membershipId"]) >= 0)
    ) {
      return false;
    }
    previous = mention["membershipId"];
  }
  return true;
}

function isCommentMentionCandidate(
  value: unknown,
): value is CommentMentionCandidate {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, ["membershipId", "displayName", "audience"]) &&
    typeof value["membershipId"] === "string" &&
    uuidV7Pattern.test(value["membershipId"]) &&
    isCanonicalDisplayName(value["displayName"], 200) &&
    value["audience"] === "operator"
  );
}

function isOperatorCommentRevision(
  value: unknown,
): value is OperatorCommentRevision {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, [
      "projection",
      "revision",
      "bodyMarkdown",
      "bodyHtml",
      "attachments",
      "mentions",
      "reason",
      "editedAt",
    ]) &&
    value["projection"] === "operator" &&
    isResourceVersion(value["revision"]) &&
    isSafeCommentMarkdown(value["bodyMarkdown"]) &&
    typeof value["bodyHtml"] === "string" &&
    Array.from(value["bodyHtml"]).length <= 100_000 &&
    isOperatorCommentAttachments(value["attachments"]) &&
    isOperatorCommentMentions(value["mentions"]) &&
    isCommentEditReason(value["reason"]) &&
    isCanonicalInstant(value["editedAt"])
  );
}

function isSafeCommentFilename(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !hasGoTrimSpaceAtEdge(value) &&
    value !== "." &&
    value !== ".." &&
    new TextEncoder().encode(value).length <= 255 &&
    !hasControlCharacters(value) &&
    !hasBidiControlCharacters(value) &&
    !value.includes("/") &&
    !value.includes("\\") &&
    !hasUnpairedSurrogate(value)
  );
}

function hasCanonicalCommentTimeline(
  createdAt: string,
  updatedAt: string,
  editableUntil: string,
): boolean {
  const created = parseRfc3339Instant(createdAt);
  const updated = parseRfc3339Instant(updatedAt);
  const editable = parseRfc3339Instant(editableUntil);
  return (
    created !== undefined &&
    updated !== undefined &&
    editable !== undefined &&
    editable === created + 15n * 60n * 1_000_000_000n &&
    updated >= created &&
    updated <= editable
  );
}

function compareUtf8Bytewise(left: string, right: string): number {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

interface CommentAuthorRecord {
  displayName: string;
  membershipId?: string;
  origin: "customer" | "operator";
  principalType?: "service_account" | "system";
  serviceAccountId?: string;
}

function isCommentAuthor(value: unknown): value is CommentAuthorRecord {
  return (
    isRecord(value) &&
    typeof value["displayName"] === "string" &&
    ["customer", "operator"].includes(String(value["origin"]))
  );
}

function isCommentVisibility(
  value: unknown,
): value is TicketComment["visibility"] {
  return value === "private" || value === "public";
}

function isCustomerActivityKind(
  value: unknown,
): value is Extract<ActivityProjection, { projection: "customer" }>["kind"] {
  return typeof value === "string" && customerActivityKinds.has(value);
}

function isOperatorActivityKind(
  value: unknown,
): value is Extract<ActivityProjection, { projection: "operator" }>["kind"] {
  return typeof value === "string" && operatorActivityKinds.has(value);
}

function isOperatorAlertCaseLink(
  value: AlertCaseLinkView,
): value is Extract<AlertCaseLinkView, { projection: "operator" }> {
  return value.projection === "operator";
}

function isAlertCaseUnlinkReceipt(
  value: unknown,
  tenantId: string,
  alertId: string,
  request: AlertCaseUnlinkRequest,
): value is AlertCaseUnlinkReceipt {
  return (
    isRecord(value) &&
    hasOnlyKeys(value, [
      "tenantId",
      "alertId",
      "caseId",
      "linkId",
      "previousAlertVersion",
      "alertVersion",
      "previousCaseVersion",
      "caseVersion",
      "retractedAt",
      "replayed",
    ]) &&
    value["tenantId"] === tenantId &&
    value["alertId"] === alertId &&
    value["caseId"] === request.caseId &&
    typeof value["linkId"] === "string" &&
    uuidV7Pattern.test(value["linkId"]) &&
    value["previousAlertVersion"] === request.expectedVersion &&
    value["previousCaseVersion"] === request.expectedCaseVersion &&
    value["alertVersion"] === request.expectedVersion + 1 &&
    value["caseVersion"] === request.expectedCaseVersion + 1 &&
    isResourceVersion(value["alertVersion"]) &&
    isResourceVersion(value["caseVersion"]) &&
    isCanonicalInstant(value["retractedAt"]) &&
    typeof value["replayed"] === "boolean"
  );
}

function isAlertCaseLinkView(value: unknown): value is AlertCaseLinkView {
  if (
    !isRecord(value) ||
    typeof value["id"] !== "string" ||
    !uuidV7Pattern.test(value["id"]) ||
    typeof value["tenantId"] !== "string" ||
    !uuidV7Pattern.test(value["tenantId"]) ||
    typeof value["alertId"] !== "string" ||
    !uuidV7Pattern.test(value["alertId"]) ||
    typeof value["caseId"] !== "string" ||
    !uuidV7Pattern.test(value["caseId"]) ||
    typeof value["linkedAt"] !== "string" ||
    !isCanonicalInstant(value["linkedAt"]) ||
    (value["relationType"] !== "correlation" &&
      value["relationType"] !== "escalation")
  ) {
    return false;
  }
  if (value["projection"] === "customer") return true;
  return (
    value["projection"] === "operator" &&
    typeof value["linkedBy"] === "string" &&
    uuidV7Pattern.test(value["linkedBy"]) &&
    typeof value["escalationReason"] === "string" &&
    isResourceVersion(value["sourceAlertVersion"]) &&
    isEscalationCopySelection(value["copySelection"]) &&
    isCopiedFieldSnapshot(value["copiedFieldSnapshot"])
  );
}

function isEscalationCopySelection(
  value: unknown,
): value is EscalationCopySelection {
  if (!isRecord(value)) return false;
  return (
    (value["fields"] === undefined ||
      (isStringArray(value["fields"], 6) &&
        value["fields"].every((field) => escalationCopyFields.has(field)))) &&
    (value["customFieldKeys"] === undefined ||
      (isStringArray(value["customFieldKeys"], 100) &&
        value["customFieldKeys"].every((key) =>
          customFieldKeyPattern.test(key),
        ))) &&
    [
      "iocIds",
      "assetIds",
      "attachmentIds",
      "contactIds",
      "publicCommentIds",
    ].every((key) => value[key] === undefined || isStringArray(value[key], 100))
  );
}

function isCopiedFieldSnapshot(
  value: unknown,
): value is AlertCaseCopiedFieldSnapshot {
  if (!isRecord(value)) return false;
  return (
    (value["fields"] === undefined || isCustomFieldValues(value["fields"])) &&
    (value["customFields"] === undefined ||
      isCustomFieldValues(value["customFields"])) &&
    [
      "iocIds",
      "assetIds",
      "attachmentIds",
      "contactIds",
      "publicCommentIds",
    ].every((key) => value[key] === undefined || isStringArray(value[key], 100))
  );
}

function isStringArray(value: unknown, maximum: number): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    value.every((item) => typeof item === "string")
  );
}

function isTicketSideEffectPlan(value: unknown): boolean {
  if (!Array.isArray(value) || value.length < 2 || value.length > 4) {
    return false;
  }
  const effects = new Set(value);
  return (
    effects.size === value.length &&
    effects.has("activity") &&
    effects.has("audit") &&
    value.every((effect) =>
      ["activity", "audit", "sla", "notification"].includes(String(effect)),
    )
  );
}

function isResourceVersion(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 2_147_483_647
  );
}

export class TicketingApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "TicketingApiError";
  }
}

export function describeTicketingError(
  value: unknown,
  fallback: string,
): string {
  return value instanceof TicketingApiError && value.message.trim() !== ""
    ? value.message
    : fallback;
}
