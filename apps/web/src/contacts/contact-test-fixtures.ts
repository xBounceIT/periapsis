import type {
  AlertCustomerProjection,
  CustomerActivity,
  CustomerComment,
  CustomerContact,
  CustomerContactGroup,
  CustomerPortalAttachment,
  CustomerPortalContact,
} from "@periapsis/contracts";

import type { ContactPortalApi, PortalComment } from "./contact-api";

export const contactTenantId = "01991c20-7d5f-7000-8000-000000000001";
export const contactId = "01991c20-7d5f-7000-8000-000000000002";
export const portalAlertId = "01991c20-7d5f-7000-8000-000000000003";
export const portalAttachmentId = "01991c20-7d5f-7000-8000-000000000008";

export const customerContactFixture = {
  active: true,
  contactClass: "customer",
  createdAt: "2026-08-25T09:00:00Z",
  email: "shared-incident@example.invalid",
  emailAllowed: true,
  escalationPriority: 50,
  firstName: "Ari",
  function: "Incident liaison",
  id: contactId,
  language: "en",
  lastName: "Customer",
  notificationCategories: ["incident"],
  notificationWindows: [{ endMinute: 1020, isoWeekday: 1, startMinute: 540 }],
  tags: ["region_eu"],
  tenantId: contactTenantId,
  timezone: "Europe/Rome",
  updatedAt: "2026-08-25T09:00:00Z",
  version: 1,
} satisfies CustomerContact;

export const portalContactFixture = {
  active: true,
  email: customerContactFixture.email,
  emailAllowed: true,
  firstName: customerContactFixture.firstName,
  function: customerContactFixture.function,
  id: contactId,
  language: "en",
  lastName: customerContactFixture.lastName,
  notificationCategories: ["incident"],
  notificationWindows: customerContactFixture.notificationWindows,
  timezone: "Europe/Rome",
  version: 1,
} satisfies CustomerPortalContact;

export const customerContactGroupFixture = {
  createdAt: "2026-08-25T09:00:00Z",
  description: "Primary incident contacts",
  id: "01991c20-7d5f-7000-8000-000000000004",
  key: "primary_contacts",
  memberIds: [contactId],
  mode: "manual",
  name: "Primary contacts",
  tenantId: contactTenantId,
  updatedAt: "2026-08-25T09:00:00Z",
  version: 1,
} satisfies CustomerContactGroup;

export const portalAlertFixture = {
  alertNumber: "ALT-2026-0042",
  category: "endpoint",
  createdAt: "2026-08-25T09:00:00Z",
  customerVisible: true,
  customFields: {},
  description: "We are investigating an endpoint signal.",
  detectedAt: "2026-08-25T08:50:00Z",
  id: portalAlertId,
  priority: "high",
  projection: "customer",
  receivedAt: "2026-08-25T09:00:00Z",
  severity: "high",
  tags: ["endpoint"],
  tenantId: contactTenantId,
  title: "Endpoint signal",
  updatedAt: "2026-08-25T09:30:00Z",
  version: 1,
  visibility: "customer",
  workflow: {
    customerVisible: true,
    initial: false,
    kind: "alert",
    stateKey: "investigating",
    terminal: false,
    version: 1,
    workflowId: "01991c20-7d5f-7000-8000-000000000005",
  },
} satisfies AlertCustomerProjection;

export const portalCommentFixture = {
  author: { audience: "operator", displayName: "Incident team" },
  attachments: [],
  bodyHtml:
    "<img src=x onerror=alert(1)><strong>unsafe transport field</strong>",
  bodyMarkdown: "**Public update** from the incident team.",
  createdAt: "2026-08-25T09:20:00Z",
  canEdit: false,
  editableUntil: "2026-08-25T09:35:00Z",
  id: "01991c20-7d5f-7000-8000-000000000006",
  origin: "api",
  projection: "customer",
  resourceId: portalAlertId,
  resourceKind: "alert",
  revision: 1,
  tenantId: contactTenantId,
  updatedAt: "2026-08-25T09:20:00Z",
  visibility: "public",
} satisfies CustomerComment;

export const portalSafeCommentFixture = (() => {
  const { bodyHtml: _bodyHtml, ...comment } = portalCommentFixture;
  return comment;
})() satisfies PortalComment;

export const portalActivityFixture = {
  actor: { displayName: "Incident team", origin: "operator" },
  id: "01991c20-7d5f-7000-8000-000000000007",
  kind: "status_changed",
  occurredAt: "2026-08-25T09:15:00Z",
  projection: "customer",
  resourceId: portalAlertId,
  resourceKind: "alert",
  summary: "Investigation started",
  tenantId: contactTenantId,
} satisfies CustomerActivity;

export const portalAttachmentFixture = {
  downloadable: true,
  id: portalAttachmentId,
  originalFilename: "customer-incident-summary.pdf",
  projection: "customer",
  resourceId: portalAlertId,
  resourceKind: "alert",
  uploadedAt: "2026-08-25T09:25:00Z",
} satisfies CustomerPortalAttachment;

const unsupported = async (): Promise<never> => {
  throw new Error("Unexpected ContactPortalApi call in test");
};

export function createContactPortalApi(
  overrides: Partial<ContactPortalApi> = {},
): ContactPortalApi {
  return {
    archiveContact: unsupported,
    createContact: unsupported,
    createGroup: unsupported,
    createPortalComment: unsupported,
    previewPortalComment: unsupported,
    editPortalComment: unsupported,
    listPortalCommentRevisions: unsupported,
    downloadPortalTicket: unsupported,
    getContact: unsupported,
    getGroup: unsupported,
    getPortalContact: async () => ({
      etag: '"v1"',
      value: portalContactFixture,
    }),
    getPortalTicket: async () => ({ etag: '"v1"', value: portalAlertFixture }),
    listContacts: async () => ({ items: [customerContactFixture] }),
    listGroups: async () => ({ items: [customerContactGroupFixture] }),
    listPortalActivities: async () => ({ items: [portalActivityFixture] }),
    listPortalAttachments: async () => ({ items: [portalAttachmentFixture] }),
    listPortalComments: async () => ({ items: [portalSafeCommentFixture] }),
    listPortalTickets: async () => ({ items: [portalAlertFixture] }),
    preparePortalAttachmentDownload: unsupported,
    replaceContact: unsupported,
    replacePortalPreferences: unsupported,
    versionGroup: unsupported,
    ...overrides,
  };
}
