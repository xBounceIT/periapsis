import {
  archiveTenantCustomerContact,
  createCustomerPortalAlertComment,
  createCustomerPortalCaseComment,
  editCustomerPortalAlertComment,
  editCustomerPortalCaseComment,
  createTenantCustomerContact,
  createTenantCustomerContactGroup,
  exportCustomerPortalAlert,
  exportCustomerPortalCase,
  getCustomerPortalAlert,
  getCustomerPortalCase,
  getCustomerPortalContact,
  getTenantCustomerContact,
  getTenantCustomerContactGroup,
  listCustomerPortalAlertDfirAttachments,
  listCustomerPortalAlertActivities,
  listCustomerPortalAlertComments,
  listCustomerPortalAlerts,
  listCustomerPortalCaseDfirAttachments,
  listCustomerPortalCaseActivities,
  listCustomerPortalCaseComments,
  listCustomerPortalAlertCommentRevisions,
  listCustomerPortalCaseCommentRevisions,
  listCustomerPortalCases,
  listTenantCustomerContactGroups,
  listTenantCustomerContacts,
  prepareCustomerPortalAlertDfirAttachmentDownload,
  prepareCustomerPortalCaseDfirAttachmentDownload,
  previewCustomerPortalAlertComment,
  previewCustomerPortalCaseComment,
  replaceCustomerPortalContactPreferences,
  replaceTenantCustomerContact,
  versionTenantCustomerContactGroup,
  type AlertCustomerProjection,
  type CaseCustomerProjection,
  type CustomerActivity,
  type CustomerComment,
  type CustomerCommentPreview,
  type CustomerCommentRevision,
  type CustomerPortalCommentEditRequest,
  type CustomerPortalCommentPreviewRequest,
  type CustomerContact,
  type CustomerContactGroup,
  type CustomerContactGroupCreate,
  type CustomerContactGroupVersionWrite,
  type CustomerContactPreferences,
  type CustomerContactWrite,
  type CustomerPortalAttachment,
  type CustomerPortalContact,
  type CustomerPortalPreparedAttachmentDownload,
} from "@periapsis/contracts";

import { currentInstant, parseRfc3339Instant } from "../lib/rfc3339-instant";
import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
  isCanonicalDisplayName,
} from "../lib/canonical-display-name";
import {
  hasBidiControlCharacters,
  hasControlCharacters,
  hasForbiddenCommentMarkdownCharacters,
} from "../lib/text-validation";
import { sessionAwareFetch } from "../lib/session-transition-transport";

export interface ContactPage<T> {
  items: T[];
  nextCursor?: string;
}

export interface Versioned<T> {
  etag: string;
  value: T;
}

export type PortalComment = Omit<CustomerComment, "bodyHtml">;
export type PortalCommentPreview = Omit<CustomerCommentPreview, "bodyHtml">;
export type PortalCommentRevision = Omit<CustomerCommentRevision, "bodyHtml">;

export interface PortalCommentRevisionPage {
  items: PortalCommentRevision[];
  nextAfterRevision?: number;
}

export interface VersionedPortalCommentMutation {
  etag: string;
  replayed: boolean;
  value: PortalComment;
}

export interface CustomerPortalExportFile {
  blob: Blob;
  filename: "periapsis-customer-alert.csv" | "periapsis-customer-case.csv";
}

interface MutationContext {
  csrfToken: string;
  idempotencyKey: string;
  tenantId: string;
}

interface VersionMutationContext extends MutationContext {
  etag: string;
}

export interface ContactPortalApi {
  listContacts(input: {
    active?: boolean;
    after?: string;
    search?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<CustomerContact>>;
  getContact(input: {
    contactId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<CustomerContact>>;
  createContact(
    input: MutationContext & { body: CustomerContactWrite },
  ): Promise<Versioned<CustomerContact>>;
  replaceContact(
    input: VersionMutationContext & {
      body: CustomerContactWrite;
      contactId: string;
    },
  ): Promise<Versioned<CustomerContact>>;
  archiveContact(
    input: VersionMutationContext & { contactId: string; reason: string },
  ): Promise<Versioned<CustomerContact>>;
  listGroups(input: {
    after?: string;
    search?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<CustomerContactGroup>>;
  getGroup(input: {
    groupId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<CustomerContactGroup>>;
  createGroup(
    input: MutationContext & { body: CustomerContactGroupCreate },
  ): Promise<Versioned<CustomerContactGroup>>;
  versionGroup(
    input: VersionMutationContext & {
      body: CustomerContactGroupVersionWrite;
      groupId: string;
    },
  ): Promise<Versioned<CustomerContactGroup>>;
  getPortalContact(input: {
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<CustomerPortalContact>>;
  replacePortalPreferences(
    input: VersionMutationContext & { body: CustomerContactPreferences },
  ): Promise<Versioned<CustomerPortalContact>>;
  listPortalTickets(input: {
    after?: string;
    kind: "alert" | "case";
    search?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<AlertCustomerProjection | CaseCustomerProjection>>;
  getPortalTicket(input: {
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<AlertCustomerProjection | CaseCustomerProjection>>;
  downloadPortalTicket(input: {
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomerPortalExportFile>;
  listPortalAttachments(input: {
    after?: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<CustomerPortalAttachment>>;
  preparePortalAttachmentDownload(input: {
    attachmentId: string;
    csrfToken: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CustomerPortalPreparedAttachmentDownload>;
  listPortalComments(input: {
    after?: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<PortalComment>>;
  createPortalComment(
    input: MutationContext & {
      attachmentIds?: string[];
      bodyMarkdown: string;
      kind: "alert" | "case";
      resourceId: string;
      signal?: AbortSignal;
    },
  ): Promise<PortalComment>;
  previewPortalComment(input: {
    attachmentIds?: string[];
    bodyMarkdown: string;
    csrfToken: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<PortalCommentPreview>;
  editPortalComment(
    input: MutationContext & {
      attachmentIds?: string[];
      bodyMarkdown: string;
      commentId: string;
      etag: string;
      kind: "alert" | "case";
      resourceId: string;
      signal?: AbortSignal;
    },
  ): Promise<VersionedPortalCommentMutation>;
  listPortalCommentRevisions(input: {
    afterRevision?: number;
    commentId: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<PortalCommentRevisionPage>;
  listPortalActivities(input: {
    after?: string;
    kind: "alert" | "case";
    resourceId: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<ContactPage<CustomerActivity>>;
}

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const strongEntityTagPattern = /^"v([1-9]\d{0,9})"$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}(?![\s\S])/u;
const commentEntityTagPattern = /^"comment-r([1-9]\d{0,9})"(?![\s\S])/u;
const portalAttachmentCursorPattern = /^[A-Za-z0-9_-]{16,512}$/u;
const maximumCustomerPortalExportBytes = 2 * 1024 * 1024;
const maximumCustomerPortalCapabilityLifetime = 6n * 60n * 1_000_000_000n;

export const contactPortalApi: ContactPortalApi = {
  async listContacts({ active, after, search, signal, tenantId }) {
    requireTenant(tenantId);
    return projectPage(
      unwrap(
        await listTenantCustomerContacts({
          ...sameOrigin,
          path: { tenantId },
          query: {
            limit: 50,
            ...(active === undefined ? {} : { active }),
            ...(after ? { after } : {}),
            ...(search ? { search } : {}),
          },
          ...(signal ? { signal } : {}),
        }),
      ),
      (value) => projectContact(value, tenantId),
    );
  },

  async getContact({ contactId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(contactId);
    return projectVersioned(
      await getTenantCustomerContact({
        ...sameOrigin,
        path: { contactId, tenantId },
        ...(signal ? { signal } : {}),
      }),
      (value) => projectContact(value, tenantId),
    );
  },

  async createContact(input) {
    requireMutation(input);
    return projectVersioned(
      await createTenantCustomerContact({
        ...sameOrigin,
        body: input.body,
        headers: mutationHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      (value) => projectContact(value, input.tenantId),
    );
  },

  async replaceContact(input) {
    requireVersionMutation(input);
    requireResourceId(input.contactId);
    return projectVersioned(
      await replaceTenantCustomerContact({
        ...sameOrigin,
        body: input.body,
        headers: versionHeaders(input),
        path: { contactId: input.contactId, tenantId: input.tenantId },
      }),
      (value) => projectContact(value, input.tenantId),
    );
  },

  async archiveContact(input) {
    requireVersionMutation(input);
    requireResourceId(input.contactId);
    if (!input.reason.trim() || input.reason.length > 500) {
      throw new ContactApiError("An archive reason is required.");
    }
    return projectVersioned(
      await archiveTenantCustomerContact({
        ...sameOrigin,
        body: { reason: input.reason },
        headers: versionHeaders(input),
        path: { contactId: input.contactId, tenantId: input.tenantId },
      }),
      (value) => projectContact(value, input.tenantId),
    );
  },

  async listGroups({ after, search, signal, tenantId }) {
    requireTenant(tenantId);
    return projectPage(
      unwrap(
        await listTenantCustomerContactGroups({
          ...sameOrigin,
          path: { tenantId },
          query: {
            limit: 50,
            ...(after ? { after } : {}),
            ...(search ? { search } : {}),
          },
          ...(signal ? { signal } : {}),
        }),
      ),
      (value) => projectGroup(value, tenantId),
    );
  },

  async getGroup({ groupId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(groupId);
    return projectVersioned(
      await getTenantCustomerContactGroup({
        ...sameOrigin,
        path: { contactGroupId: groupId, tenantId },
        ...(signal ? { signal } : {}),
      }),
      (value) => projectGroup(value, tenantId),
    );
  },

  async createGroup(input) {
    requireMutation(input);
    return projectVersioned(
      await createTenantCustomerContactGroup({
        ...sameOrigin,
        body: input.body,
        headers: mutationHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      (value) => projectGroup(value, input.tenantId),
    );
  },

  async versionGroup(input) {
    requireVersionMutation(input);
    requireResourceId(input.groupId);
    return projectVersioned(
      await versionTenantCustomerContactGroup({
        ...sameOrigin,
        body: input.body,
        headers: versionHeaders(input),
        path: { contactGroupId: input.groupId, tenantId: input.tenantId },
      }),
      (value) => projectGroup(value, input.tenantId),
    );
  },

  async getPortalContact({ signal, tenantId }) {
    requireTenant(tenantId);
    return projectVersioned(
      await getCustomerPortalContact({
        ...sameOrigin,
        path: { tenantId },
        ...(signal ? { signal } : {}),
      }),
      projectPortalContact,
    );
  },

  async replacePortalPreferences(input) {
    requireVersionMutation(input);
    return projectVersioned(
      await replaceCustomerPortalContactPreferences({
        ...sameOrigin,
        body: input.body,
        headers: versionHeaders(input),
        path: { tenantId: input.tenantId },
      }),
      projectPortalContact,
    );
  },

  async listPortalTickets({ after, kind, search, signal, tenantId }) {
    requireTenant(tenantId);
    requirePortalKind(kind);
    const options = {
      ...sameOrigin,
      path: { tenantId },
      query: {
        limit: 50,
        ...(after ? { after } : {}),
        ...(search ? { search } : {}),
      },
      ...(signal ? { signal } : {}),
    };
    if (kind === "alert") {
      return projectPage(
        unwrap(await listCustomerPortalAlerts(options)),
        (value) => projectPortalTicket(value, tenantId, "alert"),
      );
    }
    return projectPage(
      unwrap(await listCustomerPortalCases(options)),
      (value) => projectPortalTicket(value, tenantId, "case"),
    );
  },

  async getPortalTicket({ kind, resourceId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    requirePortalKind(kind);
    if (kind === "alert") {
      return projectVersioned(
        await getCustomerPortalAlert({
          ...sameOrigin,
          path: { alertId: resourceId, tenantId },
          ...(signal ? { signal } : {}),
        }),
        (value) => projectPortalTicket(value, tenantId, "alert"),
      );
    }
    return projectVersioned(
      await getCustomerPortalCase({
        ...sameOrigin,
        path: { caseId: resourceId, tenantId },
        ...(signal ? { signal } : {}),
      }),
      (value) => projectPortalTicket(value, tenantId, "case"),
    );
  },

  async downloadPortalTicket({ kind, resourceId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    requirePortalKind(kind);
    const result =
      kind === "alert"
        ? await exportCustomerPortalAlert({
            ...sameOrigin,
            cache: "no-store",
            parseAs: "blob",
            path: { alertId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          })
        : await exportCustomerPortalCase({
            ...sameOrigin,
            cache: "no-store",
            parseAs: "blob",
            path: { caseId: resourceId, tenantId },
            ...(signal ? { signal } : {}),
          });
    return projectPortalExport(result, kind);
  },

  async listPortalAttachments({ after, kind, resourceId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    requirePortalKind(kind);
    requirePortalAttachmentCursor(after);
    const request = {
      ...sameOrigin,
      cache: "no-store" as const,
      query: { limit: 50, ...(after ? { after } : {}) },
      ...(signal ? { signal } : {}),
    };
    if (kind === "alert") {
      const result = await listCustomerPortalAlertDfirAttachments({
        ...request,
        path: { alertId: resourceId, tenantId },
      });
      assertSensitiveResponse(result.response);
      return projectPortalAttachmentPage(
        unwrap(result),
        kind,
        resourceId,
        after,
      );
    }
    const result = await listCustomerPortalCaseDfirAttachments({
      ...request,
      path: { caseId: resourceId, tenantId },
    });
    assertSensitiveResponse(result.response);
    return projectPortalAttachmentPage(unwrap(result), kind, resourceId, after);
  },

  async preparePortalAttachmentDownload(input) {
    requireTenant(input.tenantId);
    requireResourceId(input.resourceId);
    requireResourceId(input.attachmentId);
    requirePortalKind(input.kind);
    if (!input.csrfToken.trim() || input.csrfToken.length > 4096) {
      throw new ContactApiError("Request integrity context is unavailable.");
    }
    const request = {
      ...sameOrigin,
      cache: "no-store" as const,
      headers: { "X-CSRF-Token": input.csrfToken },
      redirect: "error" as const,
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.kind === "alert"
        ? await prepareCustomerPortalAlertDfirAttachmentDownload({
            ...request,
            path: {
              alertId: input.resourceId,
              attachmentId: input.attachmentId,
              tenantId: input.tenantId,
            },
          })
        : await prepareCustomerPortalCaseDfirAttachmentDownload({
            ...request,
            path: {
              attachmentId: input.attachmentId,
              caseId: input.resourceId,
              tenantId: input.tenantId,
            },
          });
    assertSensitiveResponse(result.response, true);
    return projectPortalPreparedAttachmentDownload(
      unwrap(result),
      input.kind,
      input.resourceId,
      input.attachmentId,
    );
  },

  async listPortalComments({ after, kind, resourceId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    if (after !== undefined) requireResourceId(after);
    requirePortalKind(kind);
    const options = {
      ...sameOrigin,
      cache: "no-store" as const,
      query: { limit: 50, ...(after ? { after } : {}) },
      ...(signal ? { signal } : {}),
    };
    const page =
      kind === "alert"
        ? unwrap(
            await listCustomerPortalAlertComments({
              ...options,
              path: { alertId: resourceId, tenantId },
            }),
          )
        : unwrap(
            await listCustomerPortalCaseComments({
              ...options,
              path: { caseId: resourceId, tenantId },
            }),
          );
    return projectPortalCommentPage(page, tenantId, kind, resourceId);
  },

  async createPortalComment(input) {
    requireMutation(input);
    requireResourceId(input.resourceId);
    requirePortalKind(input.kind);
    requirePortalCommentDraft(input.bodyMarkdown, input.attachmentIds);
    const options = {
      ...sameOrigin,
      body: {
        bodyMarkdown: input.bodyMarkdown,
        ...(input.attachmentIds ? { attachmentIds: input.attachmentIds } : {}),
      },
      cache: "no-store" as const,
      headers: mutationHeaders(input),
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.kind === "alert"
        ? await createCustomerPortalAlertComment({
            ...options,
            path: {
              alertId: input.resourceId,
              tenantId: input.tenantId,
            },
          })
        : await createCustomerPortalCaseComment({
            ...options,
            path: { caseId: input.resourceId, tenantId: input.tenantId },
          });
    const comment = projectPortalComment(
      unwrap(result),
      input.tenantId,
      input.kind,
      input.resourceId,
    );
    requirePortalCommentReceipt(result.response, comment.revision);
    return comment;
  },

  async previewPortalComment(input) {
    requireTenant(input.tenantId);
    requireResourceId(input.resourceId);
    requirePortalKind(input.kind);
    requirePortalCsrf(input.csrfToken);
    requirePortalCommentDraft(input.bodyMarkdown, input.attachmentIds);
    const body: CustomerPortalCommentPreviewRequest = {
      bodyMarkdown: input.bodyMarkdown,
      ...(input.attachmentIds ? { attachmentIds: input.attachmentIds } : {}),
    };
    const request = {
      ...sameOrigin,
      body,
      cache: "no-store" as const,
      headers: { "X-CSRF-Token": input.csrfToken },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const value: unknown = unwrap(
      input.kind === "alert"
        ? await previewCustomerPortalAlertComment({
            ...request,
            path: { alertId: input.resourceId, tenantId: input.tenantId },
          })
        : await previewCustomerPortalCaseComment({
            ...request,
            path: { caseId: input.resourceId, tenantId: input.tenantId },
          }),
    );
    return projectPortalCommentPreview(value);
  },

  async editPortalComment(input) {
    requireMutation(input);
    requireResourceId(input.resourceId);
    requireResourceId(input.commentId);
    requirePortalKind(input.kind);
    requirePortalCommentDraft(input.bodyMarkdown, input.attachmentIds);
    const expectedRevision = requirePortalCommentEtag(input.etag);
    const body: CustomerPortalCommentEditRequest = {
      bodyMarkdown: input.bodyMarkdown,
      ...(input.attachmentIds ? { attachmentIds: input.attachmentIds } : {}),
    };
    const request = {
      ...sameOrigin,
      body,
      cache: "no-store" as const,
      headers: { ...mutationHeaders(input), "If-Match": input.etag },
      ...(input.signal ? { signal: input.signal } : {}),
    };
    const result =
      input.kind === "alert"
        ? await editCustomerPortalAlertComment({
            ...request,
            path: {
              alertId: input.resourceId,
              commentId: input.commentId,
              tenantId: input.tenantId,
            },
          })
        : await editCustomerPortalCaseComment({
            ...request,
            path: {
              caseId: input.resourceId,
              commentId: input.commentId,
              tenantId: input.tenantId,
            },
          });
    const comment = projectPortalComment(
      unwrap(result),
      input.tenantId,
      input.kind,
      input.resourceId,
    );
    if (
      comment.id !== input.commentId ||
      comment.revision !== expectedRevision + 1
    ) {
      throw projectionMismatch(
        "The edited portal comment did not match its request.",
      );
    }
    const receipt = requirePortalCommentReceipt(
      result.response,
      comment.revision,
    );
    return { ...receipt, value: comment };
  },

  async listPortalCommentRevisions({
    afterRevision,
    commentId,
    kind,
    resourceId,
    signal,
    tenantId,
  }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    requireResourceId(commentId);
    requirePortalKind(kind);
    if (
      afterRevision !== undefined &&
      !isPortalCommentRevision(afterRevision)
    ) {
      throw new ContactApiError("A valid comment history cursor is required.");
    }
    const request = {
      ...sameOrigin,
      cache: "no-store" as const,
      query: { limit: 100, ...(afterRevision ? { afterRevision } : {}) },
      ...(signal ? { signal } : {}),
    };
    const value: unknown = unwrap(
      kind === "alert"
        ? await listCustomerPortalAlertCommentRevisions({
            ...request,
            path: { alertId: resourceId, commentId, tenantId },
          })
        : await listCustomerPortalCaseCommentRevisions({
            ...request,
            path: { caseId: resourceId, commentId, tenantId },
          }),
    );
    return projectPortalCommentRevisionPage(value, afterRevision);
  },

  async listPortalActivities({ after, kind, resourceId, signal, tenantId }) {
    requireTenant(tenantId);
    requireResourceId(resourceId);
    requirePortalKind(kind);
    const options = {
      ...sameOrigin,
      query: { limit: 50, ...(after ? { after } : {}) },
      ...(signal ? { signal } : {}),
    };
    const page =
      kind === "alert"
        ? unwrap(
            await listCustomerPortalAlertActivities({
              ...options,
              path: { alertId: resourceId, tenantId },
            }),
          )
        : unwrap(
            await listCustomerPortalCaseActivities({
              ...options,
              path: { caseId: resourceId, tenantId },
            }),
          );
    return projectPage(page, (value) =>
      projectPortalActivity(value, tenantId, kind, resourceId),
    );
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
  requireTenant(input.tenantId);
  requirePortalCsrf(input.csrfToken);
  if (!idempotencyKeyPattern.test(input.idempotencyKey)) {
    throw new ContactApiError("A valid retry key is required.");
  }
}

function requirePortalCsrf(value: string): void {
  if (
    !value.trim() ||
    value.length > 4096 ||
    value.includes(",") ||
    hasControlCharacters(value)
  ) {
    throw new ContactApiError("Request integrity context is unavailable.");
  }
}

function requirePortalKind(value: string): asserts value is "alert" | "case" {
  if (value !== "alert" && value !== "case") {
    throw new ContactApiError("A valid portal resource kind is required.");
  }
}

function requireVersionMutation(input: VersionMutationContext): void {
  requireMutation(input);
  if (!strongEntityTagPattern.test(input.etag)) {
    throw new ContactApiError("A current strong entity tag is required.");
  }
}

function requireTenant(value: string): void {
  if (!uuidPattern.test(value)) {
    throw new ContactApiError("A valid tenant context is required.");
  }
}

function requireResourceId(value: string): void {
  if (!uuidPattern.test(value)) {
    throw new ContactApiError("A valid resource identifier is required.");
  }
}

function requirePortalAttachmentCursor(value: string | undefined): void {
  if (value !== undefined && !portalAttachmentCursorPattern.test(value)) {
    throw new ContactApiError("A valid attachment cursor is required.");
  }
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw toContactApiError(result.response);
}

function projectVersioned<T>(
  result: GeneratedResult<T>,
  project: (value: T) => T,
): Versioned<T> {
  const value = project(unwrap(result));
  const version = versionOf(value);
  const etag = result.response?.headers.get("ETag");
  const match = etag ? strongEntityTagPattern.exec(etag) : null;
  if (!etag || !match || Number(match[1]) !== version) {
    throw projectionMismatch("The API omitted the current contact version.");
  }
  return { etag, value };
}

function projectPage<T, U = T>(
  value: { items: T[]; nextCursor?: string },
  project: (item: T) => U,
): ContactPage<U> {
  if (
    !isRecord(value) ||
    !Array.isArray(value.items) ||
    value.items.length > 100
  ) {
    throw projectionMismatch();
  }
  if (
    value.nextCursor !== undefined &&
    (typeof value.nextCursor !== "string" || value.nextCursor.length === 0)
  ) {
    throw projectionMismatch();
  }
  return {
    items: value.items.map(project),
    ...(value.nextCursor ? { nextCursor: value.nextCursor } : {}),
  };
}

function projectPortalExport(
  result: GeneratedResult<Blob | File>,
  kind: "alert" | "case",
): CustomerPortalExportFile {
  const blob = unwrap(result);
  const response = result.response;
  const filename =
    kind === "alert"
      ? "periapsis-customer-alert.csv"
      : "periapsis-customer-case.csv";
  if (
    !(blob instanceof Blob) ||
    blob.size === 0 ||
    blob.size > maximumCustomerPortalExportBytes ||
    !response ||
    !isCustomerPortalCSVContentType(response.headers.get("Content-Type")) ||
    !hasNoStoreDirective(response.headers.get("Cache-Control")) ||
    response.headers.get("Content-Disposition") !==
      `attachment; filename="${filename}"` ||
    response.headers.get("X-Content-Type-Options") !== "nosniff"
  ) {
    throw projectionMismatch(
      "The server returned an invalid customer export response.",
    );
  }
  return { blob, filename };
}

const portalAttachmentKeys = new Set([
  "projection",
  "id",
  "resourceKind",
  "resourceId",
  "originalFilename",
  "uploadedAt",
  "downloadable",
]);
const portalAttachmentPageKeys = new Set(["items", "nextCursor"]);
const portalPreparedAttachmentDownloadKeys = new Set([
  "attachment",
  "downloadUrl",
  "expiresAt",
]);

function projectPortalAttachmentPage(
  value: { items: CustomerPortalAttachment[]; nextCursor?: string },
  kind: "alert" | "case",
  resourceId: string,
  after: string | undefined,
): ContactPage<CustomerPortalAttachment> {
  assertExactKeys(value, portalAttachmentPageKeys);
  if (
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    (value.nextCursor !== undefined &&
      (!portalAttachmentCursorPattern.test(value.nextCursor) ||
        value.nextCursor === after ||
        value.items.length === 0))
  ) {
    throw projectionMismatch();
  }
  const items = value.items.map((item) =>
    projectPortalAttachment(item, kind, resourceId),
  );
  if (new Set(items.map((item) => item.id)).size !== items.length) {
    throw projectionMismatch();
  }
  return {
    items,
    ...(value.nextCursor === undefined ? {} : { nextCursor: value.nextCursor }),
  };
}

function projectPortalAttachment(
  value: CustomerPortalAttachment,
  kind: "alert" | "case",
  resourceId: string,
): CustomerPortalAttachment {
  assertExactKeys(value, portalAttachmentKeys);
  if (
    value.projection !== "customer" ||
    value.resourceKind !== kind ||
    value.resourceId !== resourceId ||
    !value.downloadable ||
    !uuidPattern.test(value.id) ||
    !safePortalFilename(value.originalFilename) ||
    parseRfc3339Instant(value.uploadedAt) === undefined
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectPortalPreparedAttachmentDownload(
  value: CustomerPortalPreparedAttachmentDownload,
  kind: "alert" | "case",
  resourceId: string,
  attachmentId: string,
): CustomerPortalPreparedAttachmentDownload {
  assertExactKeys(value, portalPreparedAttachmentDownloadKeys);
  const attachment = projectPortalAttachment(
    value.attachment,
    kind,
    resourceId,
  );
  if (attachment.id !== attachmentId) throw projectionMismatch();
  validatePortalCapability(value.downloadUrl, value.expiresAt);
  return {
    attachment,
    downloadUrl: value.downloadUrl,
    expiresAt: value.expiresAt,
  };
}

function assertSensitiveResponse(
  response: Response | undefined,
  requireNoReferrer = false,
): void {
  if (
    !response ||
    !hasNoStoreDirective(response.headers.get("Cache-Control")) ||
    (requireNoReferrer &&
      response.headers.get("Referrer-Policy")?.trim().toLowerCase() !==
        "no-referrer")
  ) {
    throw projectionMismatch(
      "The server returned an unsafe customer attachment response.",
    );
  }
}

function safePortalFilename(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 1024 &&
    value.trim().length > 0 &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0);
      return (
        character === "\\" ||
        character === "/" ||
        codePoint === undefined ||
        codePoint <= 31 ||
        codePoint === 127
      );
    })
  );
}

function validatePortalCapability(value: string, expiresAt: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw projectionMismatch();
  }
  const expiry = parseRfc3339Instant(expiresAt);
  const now = currentInstant();
  if (
    value.length > 8192 ||
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    !parsed.hostname ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    expiry === undefined ||
    expiry <= now ||
    expiry > now + maximumCustomerPortalCapabilityLifetime
  ) {
    throw projectionMismatch();
  }
}

function hasNoStoreDirective(value: string | null): boolean {
  return (
    value
      ?.split(",")
      .map((directive) => directive.trim().toLowerCase())
      .includes("no-store") ?? false
  );
}

function isCustomerPortalCSVContentType(value: string | null): boolean {
  if (value === null) return false;
  const parts = value
    .split(";")
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);
  return parts[0] === "text/csv" && parts.includes("charset=utf-8");
}

function projectContact(value: CustomerContact, tenantId: string) {
  if (!isRecord(value) || value.tenantId !== tenantId)
    throw projectionMismatch();
  assertContactIdentity(value.id, value.version);
  if (
    typeof value.email !== "string" ||
    typeof value.firstName !== "string" ||
    typeof value.lastName !== "string" ||
    !Array.isArray(value.notificationWindows)
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectGroup(value: CustomerContactGroup, tenantId: string) {
  if (!isRecord(value) || value.tenantId !== tenantId)
    throw projectionMismatch();
  assertContactIdentity(value.id, value.version);
  if (
    (value.mode !== "manual" && value.mode !== "dynamic") ||
    !Array.isArray(value.memberIds) ||
    (value.mode === "manual" && value.rule !== undefined) ||
    (value.mode === "dynamic" && !isRecord(value.rule))
  ) {
    throw projectionMismatch();
  }
  return value;
}

const portalContactAllowedKeys = new Set([
  "id",
  "firstName",
  "lastName",
  "email",
  "phone",
  "function",
  "language",
  "timezone",
  "notificationCategories",
  "notificationWindows",
  "emailAllowed",
  "active",
  "version",
]);

function projectPortalContact(value: CustomerPortalContact) {
  assertExactKeys(value, portalContactAllowedKeys);
  assertContactIdentity(value.id, value.version);
  if (!value.active) throw projectionMismatch();
  return value;
}

const portalAlertKeys = new Set([
  "projection",
  "id",
  "tenantId",
  "alertNumber",
  "title",
  "description",
  "workflow",
  "severity",
  "priority",
  "category",
  "detectedAt",
  "receivedAt",
  "visibility",
  "customerVisible",
  "tags",
  "customFields",
  "version",
  "createdAt",
  "updatedAt",
]);
const portalCaseKeys = new Set([
  "projection",
  "id",
  "tenantId",
  "caseNumber",
  "title",
  "summary",
  "description",
  "workflow",
  "severity",
  "priority",
  "category",
  "detectionTime",
  "openedAt",
  "visibility",
  "customerVisible",
  "tags",
  "customFields",
  "version",
  "createdAt",
  "updatedAt",
]);

function projectPortalTicket<
  T extends AlertCustomerProjection | CaseCustomerProjection,
>(value: T, tenantId: string, kind: "alert" | "case"): T {
  assertExactKeys(value, kind === "alert" ? portalAlertKeys : portalCaseKeys);
  if (
    value.projection !== "customer" ||
    value.tenantId !== tenantId ||
    value.visibility !== "customer" ||
    !value.customerVisible
  ) {
    throw projectionMismatch();
  }
  assertContactIdentity(value.id, value.version);
  return value;
}

const portalCommentKeys = new Set([
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
  "revision",
  "canEdit",
  "editableUntil",
  "createdAt",
  "updatedAt",
]);

function projectPortalComment(
  value: unknown,
  tenantId: string,
  kind: "alert" | "case",
  resourceId: string,
): PortalComment {
  assertExactKeys(value, portalCommentKeys);
  if (
    !isRecord(value) ||
    value.projection !== "customer" ||
    value.visibility !== "public" ||
    value.tenantId !== tenantId ||
    value.resourceKind !== kind ||
    value.resourceId !== resourceId ||
    typeof value.id !== "string" ||
    !uuidPattern.test(value.id) ||
    !isPortalCommentOrigin(value.origin) ||
    !isSafePortalMarkdown(value.bodyMarkdown) ||
    typeof value.bodyHtml !== "string" ||
    Array.from(value.bodyHtml).length > 100_000 ||
    !isPortalCommentAuthor(value.author) ||
    !isPortalCommentAttachments(value.attachments) ||
    !isPortalCommentRevision(value.revision) ||
    typeof value.canEdit !== "boolean" ||
    (value.canEdit &&
      (value.origin !== "customer_portal" ||
        value.author.audience !== "customer")) ||
    !isPortalInstant(value.editableUntil) ||
    !isPortalInstant(value.createdAt) ||
    !isPortalInstant(value.updatedAt) ||
    !hasCanonicalPortalCommentTimeline(
      value.createdAt,
      value.updatedAt,
      value.editableUntil,
    ) ||
    !isPortalCommentOriginAudienceCoherent(value.origin, value.author.audience)
  ) {
    throw projectionMismatch();
  }
  return {
    projection: "customer",
    id: value.id,
    tenantId,
    resourceKind: kind,
    resourceId,
    origin: value.origin,
    visibility: "public",
    bodyMarkdown: value.bodyMarkdown,
    author: { ...value.author },
    attachments: value.attachments.map((attachment) => ({ ...attachment })),
    revision: value.revision,
    canEdit: value.canEdit,
    editableUntil: value.editableUntil,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  };
}

function projectPortalCommentPage(
  value: unknown,
  tenantId: string,
  kind: "alert" | "case",
  resourceId: string,
): ContactPage<PortalComment> {
  assertExactKeys(value, new Set(["items", "nextCursor"]));
  if (
    !isRecord(value) ||
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    (value.nextCursor !== undefined &&
      (typeof value.nextCursor !== "string" ||
        !uuidPattern.test(value.nextCursor)))
  ) {
    throw projectionMismatch("The portal comment page was invalid.");
  }
  const ids = new Set<string>();
  const items = value.items.map((item) => {
    const comment = projectPortalComment(item, tenantId, kind, resourceId);
    if (ids.has(comment.id)) {
      throw projectionMismatch(
        "The portal comment page contained duplicate comments.",
      );
    }
    ids.add(comment.id);
    return comment;
  });
  return {
    items,
    ...(typeof value.nextCursor === "string"
      ? { nextCursor: value.nextCursor }
      : {}),
  };
}

const portalCommentPreviewKeys = new Set([
  "visibility",
  "bodyMarkdown",
  "bodyHtml",
  "attachments",
]);
const portalCommentRevisionKeys = new Set([
  "projection",
  "revision",
  "bodyMarkdown",
  "bodyHtml",
  "attachments",
  "editedAt",
]);

function projectPortalCommentPreview(value: unknown): PortalCommentPreview {
  assertExactKeys(value, portalCommentPreviewKeys);
  if (
    !isRecord(value) ||
    value.visibility !== "public" ||
    !isSafePortalMarkdown(value.bodyMarkdown) ||
    typeof value.bodyHtml !== "string" ||
    Array.from(value.bodyHtml).length > 100_000 ||
    !isPortalCommentAttachments(value.attachments)
  ) {
    throw projectionMismatch(
      "The portal comment preview was not safe to display.",
    );
  }
  return {
    visibility: "public",
    bodyMarkdown: value.bodyMarkdown,
    attachments: value.attachments.map((attachment) => ({ ...attachment })),
  };
}

function projectPortalCommentRevisionPage(
  value: unknown,
  afterRevision: number | undefined,
): PortalCommentRevisionPage {
  assertExactKeys(value, new Set(["items", "nextAfterRevision"]));
  if (
    !isRecord(value) ||
    !Array.isArray(value.items) ||
    value.items.length > 100 ||
    (value.nextAfterRevision !== undefined &&
      !isPortalCommentRevision(value.nextAfterRevision))
  ) {
    throw projectionMismatch("The portal comment history was invalid.");
  }
  const items: PortalCommentRevision[] = [];
  let previous = afterRevision;
  for (const revision of value.items) {
    assertExactKeys(revision, portalCommentRevisionKeys);
    if (
      !isRecord(revision) ||
      revision.projection !== "customer" ||
      !isPortalCommentRevision(revision.revision) ||
      (previous !== undefined && revision.revision >= previous) ||
      !isSafePortalMarkdown(revision.bodyMarkdown) ||
      typeof revision.bodyHtml !== "string" ||
      Array.from(revision.bodyHtml).length > 100_000 ||
      !isPortalCommentAttachments(revision.attachments) ||
      !isPortalInstant(revision.editedAt)
    ) {
      throw projectionMismatch("The portal comment history was invalid.");
    }
    items.push({
      projection: "customer",
      revision: revision.revision,
      bodyMarkdown: revision.bodyMarkdown,
      attachments: revision.attachments.map((attachment) => ({
        ...attachment,
      })),
      editedAt: revision.editedAt,
    });
    previous = revision.revision;
  }
  if (
    value.nextAfterRevision !== undefined &&
    (items.length === 0 || value.nextAfterRevision !== items.at(-1)?.revision)
  ) {
    throw projectionMismatch("The portal comment history cursor was invalid.");
  }
  return {
    items,
    ...(value.nextAfterRevision === undefined
      ? {}
      : { nextAfterRevision: value.nextAfterRevision }),
  };
}

function requirePortalCommentDraft(
  bodyMarkdown: string,
  attachmentIds: string[] | undefined,
): void {
  if (
    !isSafePortalMarkdown(bodyMarkdown) ||
    !isCanonicalPortalCommentIds(attachmentIds)
  ) {
    throw new ContactApiError(
      "A canonical bounded Markdown comment is required.",
    );
  }
}

function requirePortalCommentEtag(value: string): number {
  const match = commentEntityTagPattern.exec(value);
  const revision = match ? Number(match[1]) : 0;
  if (!isPortalCommentRevision(revision)) {
    throw new ContactApiError("An exact current comment revision is required.");
  }
  return revision;
}

function requirePortalCommentReceipt(
  response: Response | undefined,
  revision: number,
): { etag: string; replayed: boolean } {
  const etag = response?.headers.get("ETag");
  const replay = response?.headers.get("X-Idempotent-Replay");
  if (
    etag === null ||
    etag === undefined ||
    requirePortalCommentEtag(etag) !== revision ||
    (replay !== "true" && replay !== "false")
  ) {
    throw projectionMismatch("The portal comment receipt was invalid.");
  }
  return { etag, replayed: replay === "true" };
}

function isPortalCommentOrigin(
  value: unknown,
): value is PortalComment["origin"] {
  return (
    value === "api" ||
    value === "customer_portal" ||
    value === "escalation_copy" ||
    value === "system"
  );
}

function isPortalCommentOriginAudienceCoherent(
  origin: PortalComment["origin"],
  audience: "customer" | "operator",
): boolean {
  if (origin === "escalation_copy") return true;
  return origin === "customer_portal"
    ? audience === "customer"
    : audience === "operator";
}

function isPortalCommentAuthor(
  value: unknown,
): value is PortalComment["author"] {
  return (
    isRecord(value) &&
    Object.keys(value).length === 2 &&
    isCanonicalDisplayName(value.displayName, 200) &&
    (value.audience === "operator" || value.audience === "customer")
  );
}

function isPortalCommentAttachments(
  value: unknown,
): value is PortalComment["attachments"] {
  if (!Array.isArray(value) || value.length > 20) return false;
  let previous: string | undefined;
  for (const attachment of value) {
    if (
      !isRecord(attachment) ||
      Object.keys(attachment).length !== 3 ||
      attachment.projection !== "customer" ||
      typeof attachment.id !== "string" ||
      !uuidPattern.test(attachment.id) ||
      typeof attachment.originalFilename !== "string" ||
      attachment.originalFilename.length === 0 ||
      hasGoTrimSpaceAtEdge(attachment.originalFilename) ||
      attachment.originalFilename === "." ||
      attachment.originalFilename === ".." ||
      new TextEncoder().encode(attachment.originalFilename).length > 255 ||
      hasControlCharacters(attachment.originalFilename) ||
      hasBidiControlCharacters(attachment.originalFilename) ||
      attachment.originalFilename.includes("/") ||
      attachment.originalFilename.includes("\\") ||
      hasUnpairedSurrogate(attachment.originalFilename) ||
      (previous !== undefined && previous >= attachment.id)
    ) {
      return false;
    }
    previous = attachment.id;
  }
  return true;
}

function isCanonicalPortalCommentIds(
  value: unknown,
): value is string[] | undefined {
  if (value === undefined) return true;
  if (!Array.isArray(value)) return false;
  if (value.length > 20) return false;
  let previous: string | undefined;
  for (const id of value) {
    if (!uuidPattern.test(id) || (previous !== undefined && previous >= id)) {
      return false;
    }
    previous = id;
  }
  return true;
}

function isSafePortalMarkdown(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !hasGoTrimSpaceAtEdge(value) &&
    Array.from(value).length <= 20_000 &&
    !hasForbiddenCommentMarkdownCharacters(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isPortalCommentRevision(value: unknown): value is number {
  return (
    Number.isInteger(value) &&
    Number(value) >= 1 &&
    Number(value) <= 2_147_483_647
  );
}

function isPortalInstant(value: unknown): value is string {
  return typeof value === "string" && parseRfc3339Instant(value) !== undefined;
}

function hasCanonicalPortalCommentTimeline(
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

const portalActivityKeys = new Set([
  "projection",
  "id",
  "tenantId",
  "resourceKind",
  "resourceId",
  "kind",
  "summary",
  "actor",
  "occurredAt",
]);
const portalActivityKinds = new Set([
  "created",
  "status_changed",
  "escalated",
  "linked",
  "comment.public",
]);

function projectPortalActivity(
  value: CustomerActivity,
  tenantId: string,
  kind: "alert" | "case",
  resourceId: string,
) {
  assertExactKeys(value, portalActivityKeys);
  if (
    value.projection !== "customer" ||
    value.tenantId !== tenantId ||
    value.resourceKind !== kind ||
    value.resourceId !== resourceId ||
    !portalActivityKinds.has(value.kind) ||
    !isRecord(value.actor)
  ) {
    throw projectionMismatch();
  }
  return value;
}

function assertContactIdentity(id: string, version: number): void {
  if (!uuidPattern.test(id) || !Number.isSafeInteger(version) || version < 1) {
    throw projectionMismatch();
  }
}

function versionOf(value: unknown): number {
  if (!isRecord(value) || !Number.isSafeInteger(value["version"])) {
    throw projectionMismatch();
  }
  const version = Number(value["version"]);
  if (version < 1) throw projectionMismatch();
  return version;
}

function assertExactKeys(value: unknown, allowed: ReadonlySet<string>): void {
  if (!isRecord(value) || Object.keys(value).some((key) => !allowed.has(key))) {
    throw projectionMismatch();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionMismatch(
  message = "The server returned a contact or portal projection that was not safe to display.",
) {
  return new ContactApiError(message, undefined, "projection_mismatch");
}

function toContactApiError(response?: Response) {
  const status = response?.status;
  const messages: Record<number, string> = {
    400: "The contact request was not accepted.",
    401: "The current session was not accepted.",
    403: "The server denied this contact operation.",
    404: "The requested resource is unavailable in this projection.",
    409: "This retry key conflicts with another contact operation.",
    412: "This resource changed. Reload it before trying again.",
    413: "This incident has too many public updates for a synchronous download.",
    428: "The current resource version is required.",
    503: "A required contact dependency is unavailable.",
  };
  return new ContactApiError(
    status === undefined
      ? "The contact request could not be completed."
      : (messages[status] ?? "The contact request could not be completed."),
    status,
  );
}

export class ContactApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "ContactApiError";
  }
}
