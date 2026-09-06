import {
  archiveTenantCaseCustomerContactLink,
  linkTenantCaseCustomerContact,
  listTenantCaseCustomerContacts,
  listTenantCustomerContacts,
  type CustomerContact,
  type TicketCustomerContactEscalationProvenance,
  type TicketCustomerContactLink,
  type TicketCustomerContactRole,
} from "@periapsis/contracts";
import { z } from "zod";

import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
} from "../lib/canonical-display-name";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  hasBidiControlCharacters,
  hasControlCharacters,
} from "../lib/text-validation";

export interface CursorPage<T> {
  items: readonly T[];
  nextCursor?: string;
}

export type ActiveCaseContact = CustomerContact;
export type CaseContactLink = TicketCustomerContactLink;
export type CaseContactRole = TicketCustomerContactRole;

export interface CaseContactReadInput {
  after?: string;
  caseId: string;
  limit?: number;
  signal?: AbortSignal;
  tenantId: string;
}

export interface CaseContactLinkInput {
  caseEtag: string;
  caseId: string;
  contactId: string;
  csrfToken: string;
  expectedCaseVersion: number;
  idempotencyKey: string;
  role: CaseContactRole;
  signal?: AbortSignal;
  tenantId: string;
}

export interface CaseContactArchiveInput {
  caseId: string;
  csrfToken: string;
  expectedCaseVersion: number;
  idempotencyKey: string;
  link: CaseContactLink;
  reason: string;
  signal?: AbortSignal;
  tenantId: string;
}

export interface CaseContactApi {
  archive(input: CaseContactArchiveInput): Promise<CaseContactLink>;
  link(input: CaseContactLinkInput): Promise<CaseContactLink>;
  listActiveContacts(
    input: CaseContactReadInput,
  ): Promise<CursorPage<ActiveCaseContact>>;
  listLinks(input: CaseContactReadInput): Promise<CursorPage<CaseContactLink>>;
}

export class CaseContactApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: "projection_mismatch",
  ) {
    super(message);
    this.name = "CaseContactApiError";
  }
}

interface GeneratedResult {
  data?: unknown;
  response?: Response;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  cache: "no-store" as const,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
export const caseContactUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const cursorPattern = /^[A-Za-z0-9_-]{1,512}(?![\s\S])/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}(?![\s\S])/u;
const stableKeyPattern = /^[a-z][a-z0-9_.-]{0,63}(?![\s\S])/u;
const languagePattern = /^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/u;
const timezonePattern =
  /^(?!Local$)(?!\/)(?!.*\.\.)(?!.*\\)[A-Za-z0-9_+/-]{1,64}(?![\s\S])/u;
const canonicalInstantSchema = z
  .string()
  .min(20)
  .max(30)
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u)
  .refine((value) => parseRfc3339Instant(value) !== undefined);
const resourceVersionSchema = z.number().int().min(1).max(2_147_483_647);
const notificationWindowSchema = z
  .strictObject({
    endMinute: z.number().int().min(1).max(1440),
    isoWeekday: z.number().int().min(1).max(7),
    startMinute: z.number().int().min(0).max(1439),
  })
  .refine((value) => value.startMinute < value.endMinute);
const linkedAccountSchema = z.strictObject({
  membershipId: z.string().regex(caseContactUuidV7Pattern),
  userId: z.string().regex(caseContactUuidV7Pattern),
});
const contactSchema = z
  .strictObject({
    active: z.literal(true),
    archivedAt: z.never().optional(),
    contactClass: z.string().regex(stableKeyPattern),
    createdAt: canonicalInstantSchema,
    email: z.string().refine(isCanonicalContactEmail),
    emailAllowed: z.boolean(),
    escalationPriority: z.number().int().min(0).max(100),
    firstName: z.string().refine((value) => isCanonicalText(value, 160)),
    function: z.string().refine((value) => isCanonicalText(value, 160)),
    id: z.string().regex(caseContactUuidV7Pattern),
    language: z
      .string()
      .regex(languagePattern)
      .refine((value) => value !== "und"),
    lastName: z.string().refine((value) => isCanonicalText(value, 160)),
    linkedAccount: linkedAccountSchema.optional(),
    notificationCategories: z.array(z.string().regex(stableKeyPattern)).max(64),
    notificationWindows: z.array(notificationWindowSchema).max(64),
    phone: z
      .string()
      .refine(
        (value) => isCanonicalText(value, 64, true) && !/[<>]/u.test(value),
      )
      .optional(),
    tags: z.array(z.string().regex(stableKeyPattern)).max(100),
    tenantId: z.string().regex(caseContactUuidV7Pattern),
    timezone: z.string().regex(timezonePattern).refine(isKnownTimezone),
    updatedAt: canonicalInstantSchema,
    version: resourceVersionSchema,
  })
  .superRefine((contact, context) => {
    if (!isSameOrLaterInstant(contact.updatedAt, contact.createdAt)) {
      context.addIssue({ code: "custom", message: "Invalid contact timeline" });
    }
    validateSortedKeys(contact.notificationCategories, context);
    validateSortedKeys(contact.tags, context);
    let previousWindow: z.infer<typeof notificationWindowSchema> | undefined;
    for (const window of contact.notificationWindows) {
      if (
        previousWindow &&
        (compareWindows(previousWindow, window) >= 0 ||
          (previousWindow.isoWeekday === window.isoWeekday &&
            window.startMinute < previousWindow.endMinute))
      ) {
        context.addIssue({
          code: "custom",
          message: "Non-canonical contact windows",
        });
        break;
      }
      previousWindow = window;
    }
  });

export const caseContactApi: CaseContactApi = {
  async listLinks(input) {
    const limit = requireReadInput(input);
    const result = await listTenantCaseCustomerContacts({
      ...sameOrigin,
      path: { caseId: input.caseId, tenantId: input.tenantId },
      query: {
        limit,
        ...(input.after === undefined ? {} : { after: input.after }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    const page = projectPage(result.data, input.after, limit, (value) =>
      projectActiveLink(value, input.tenantId, input.caseId),
    );
    assertUniqueContactLinks(page.items);
    return page;
  },

  async listActiveContacts(input) {
    const limit = requireReadInput(input);
    const result = await listTenantCustomerContacts({
      ...sameOrigin,
      path: { tenantId: input.tenantId },
      query: {
        active: true,
        includeArchived: false,
        limit,
        ...(input.after === undefined ? {} : { after: input.after }),
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    return projectPage(result.data, input.after, limit, (value) =>
      projectActiveContact(value, input.tenantId),
    );
  },

  async link(input) {
    requireLinkInput(input);
    const result = await linkTenantCaseCustomerContact({
      ...sameOrigin,
      body: { contactId: input.contactId, role: input.role },
      headers: mutationHeaders(
        input.csrfToken,
        input.idempotencyKey,
        input.caseEtag,
      ),
      path: { caseId: input.caseId, tenantId: input.tenantId },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 201);
    const link = projectActiveLink(result.data, input.tenantId, input.caseId);
    if (
      link.contactId !== input.contactId ||
      link.role !== input.role ||
      link.origin !== "manual" ||
      link.escalationProvenance !== undefined ||
      link.version !== 1
    ) {
      throw projectionMismatch();
    }
    requireEntityTag(result.response, link.version);
    const location = result.response?.headers.get("Location");
    if (
      location !==
      `/api/v1/tenants/${input.tenantId}/cases/${input.caseId}/contacts/${link.id}`
    ) {
      throw projectionMismatch();
    }
    return link;
  },

  async archive(input) {
    requireArchiveInput(input);
    const result = await archiveTenantCaseCustomerContactLink({
      ...sameOrigin,
      body: {
        expectedTicketVersion: input.expectedCaseVersion,
        reason: input.reason,
      },
      headers: mutationHeaders(
        input.csrfToken,
        input.idempotencyKey,
        `"v${input.link.version}"`,
      ),
      path: {
        caseId: input.caseId,
        contactLinkId: input.link.id,
        tenantId: input.tenantId,
      },
      ...(input.signal ? { signal: input.signal } : {}),
    });
    requireStatus(result, 200);
    const archived = projectLink(
      result.data,
      input.tenantId,
      input.caseId,
      true,
    );
    if (
      archived.id !== input.link.id ||
      archived.contactId !== input.link.contactId ||
      archived.role !== input.link.role ||
      archived.origin !== input.link.origin ||
      !sameProvenance(
        archived.escalationProvenance,
        input.link.escalationProvenance,
      ) ||
      archived.version !== input.link.version + 1 ||
      archived.createdAt !== input.link.createdAt
    ) {
      throw projectionMismatch();
    }
    requireEntityTag(result.response, archived.version);
    return archived;
  },
};

function requireReadInput(input: CaseContactReadInput): number {
  requireCoordinates(input.tenantId, input.caseId);
  if (input.after !== undefined && !cursorPattern.test(input.after)) {
    throw new TypeError("A canonical contact cursor is required.");
  }
  const limit = input.limit ?? 50;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new TypeError("A bounded contact page size is required.");
  }
  return limit;
}

function requireLinkInput(input: CaseContactLinkInput): void {
  requireCoordinates(input.tenantId, input.caseId);
  if (
    !caseContactUuidV7Pattern.test(input.contactId) ||
    !isCaseContactRole(input.role)
  ) {
    throw new TypeError("A canonical active contact and role are required.");
  }
  requireMutationContext(
    input.csrfToken,
    input.idempotencyKey,
    input.expectedCaseVersion,
    input.caseEtag,
  );
}

function requireArchiveInput(input: CaseContactArchiveInput): void {
  requireCoordinates(input.tenantId, input.caseId);
  const current = projectActiveLink(input.link, input.tenantId, input.caseId);
  if (!isCanonicalText(input.reason, 500) || current.version >= 2_147_483_647) {
    throw new TypeError(
      "A bounded archive reason and current link are required.",
    );
  }
  requireMutationContext(
    input.csrfToken,
    input.idempotencyKey,
    input.expectedCaseVersion,
    `"v${input.expectedCaseVersion}"`,
  );
}

function requireMutationContext(
  csrfToken: string,
  idempotencyKey: string,
  expectedCaseVersion: number,
  caseEtag: string,
): void {
  if (
    !Number.isSafeInteger(expectedCaseVersion) ||
    expectedCaseVersion < 1 ||
    expectedCaseVersion >= 2_147_483_647 ||
    caseEtag !== `"v${expectedCaseVersion}"` ||
    csrfToken.trim() === "" ||
    hasControlCharacters(csrfToken) ||
    !idempotencyKeyPattern.test(idempotencyKey)
  ) {
    throw new TypeError("Canonical Case mutation credentials are required.");
  }
}

function requireCoordinates(tenantId: string, caseId: string): void {
  if (
    !caseContactUuidV7Pattern.test(tenantId) ||
    !caseContactUuidV7Pattern.test(caseId)
  ) {
    throw new TypeError(
      "Canonical tenant and Case UUIDv7 values are required.",
    );
  }
}

function mutationHeaders(
  csrfToken: string,
  idempotencyKey: string,
  etag: string,
) {
  return {
    "Idempotency-Key": idempotencyKey,
    "If-Match": etag,
    "X-CSRF-Token": csrfToken,
  };
}

function projectPage<T>(
  source: unknown,
  after: string | undefined,
  limit: number,
  project: (value: unknown) => T & { id: string },
): CursorPage<T> {
  if (!isRecord(source) || !hasOnlyKeys(source, ["items", "nextCursor"])) {
    throw projectionMismatch();
  }
  if (
    !Array.isArray(source["items"]) ||
    source["items"].length > limit ||
    (source["nextCursor"] !== undefined &&
      (typeof source["nextCursor"] !== "string" ||
        !cursorPattern.test(source["nextCursor"]) ||
        source["nextCursor"] === after ||
        source["items"].length === 0))
  ) {
    throw projectionMismatch();
  }
  const items: T[] = [];
  let previousId: string | undefined;
  for (const item of source["items"]) {
    const projected = project(item);
    if (previousId !== undefined && previousId >= projected.id) {
      throw projectionMismatch();
    }
    previousId = projected.id;
    items.push(projected);
  }
  return {
    items,
    ...(typeof source["nextCursor"] === "string"
      ? { nextCursor: source["nextCursor"] }
      : {}),
  };
}

function projectActiveContact(
  source: unknown,
  tenantId: string,
): ActiveCaseContact {
  const parsed = contactSchema.safeParse(source);
  if (!parsed.success || parsed.data.tenantId !== tenantId) {
    throw projectionMismatch();
  }
  const { archivedAt: _, linkedAccount, phone, ...contact } = parsed.data;
  return {
    ...contact,
    ...(linkedAccount === undefined ? {} : { linkedAccount }),
    ...(phone === undefined ? {} : { phone }),
  };
}

function projectActiveLink(
  source: unknown,
  tenantId: string,
  caseId: string,
): CaseContactLink {
  return projectLink(source, tenantId, caseId, false);
}

function projectLink(
  source: unknown,
  tenantId: string,
  caseId: string,
  archived: boolean,
): CaseContactLink {
  if (
    !isRecord(source) ||
    !hasOnlyKeys(source, [
      "id",
      "tenantId",
      "resourceKind",
      "resourceId",
      "contactId",
      "role",
      "origin",
      "escalationProvenance",
      "version",
      "createdAt",
      "archivedAt",
    ]) ||
    !caseContactUuidV7Pattern.test(String(source["id"])) ||
    source["tenantId"] !== tenantId ||
    source["resourceKind"] !== "case" ||
    source["resourceId"] !== caseId ||
    !caseContactUuidV7Pattern.test(String(source["contactId"])) ||
    !isCaseContactRole(source["role"]) ||
    (source["origin"] !== "manual" && source["origin"] !== "escalation_copy") ||
    !resourceVersionSchema.safeParse(source["version"]).success ||
    !canonicalInstantSchema.safeParse(source["createdAt"]).success ||
    (archived
      ? !canonicalInstantSchema.safeParse(source["archivedAt"]).success ||
        !isSameOrLaterInstant(
          String(source["archivedAt"]),
          String(source["createdAt"]),
        )
      : source["archivedAt"] !== undefined)
  ) {
    throw projectionMismatch();
  }
  const provenance = projectProvenance(source["escalationProvenance"]);
  if (
    (source["origin"] === "manual" && provenance !== undefined) ||
    (source["origin"] === "escalation_copy" && provenance === undefined)
  ) {
    throw projectionMismatch();
  }
  return {
    id: String(source["id"]),
    tenantId,
    resourceKind: "case",
    resourceId: caseId,
    contactId: String(source["contactId"]),
    role: source["role"],
    origin: source["origin"],
    ...(provenance === undefined ? {} : { escalationProvenance: provenance }),
    version: Number(source["version"]),
    createdAt: String(source["createdAt"]),
    ...(archived ? { archivedAt: String(source["archivedAt"]) } : {}),
  };
}

function projectProvenance(
  source: unknown,
): TicketCustomerContactEscalationProvenance | undefined {
  if (source === undefined) return undefined;
  if (
    !isRecord(source) ||
    !hasOnlyKeys(source, ["sourceAlertId", "sourceAlertVersion"]) ||
    !caseContactUuidV7Pattern.test(String(source["sourceAlertId"])) ||
    !resourceVersionSchema.safeParse(source["sourceAlertVersion"]).success
  ) {
    throw projectionMismatch();
  }
  return {
    sourceAlertId: String(source["sourceAlertId"]),
    sourceAlertVersion: Number(source["sourceAlertVersion"]),
  };
}

function requireStatus(result: GeneratedResult, expected: number): void {
  const response = result.response;
  if (!response || !hasNoStore(response.headers.get("Cache-Control"))) {
    throw projectionMismatch();
  }
  if (response.status !== expected) {
    throw new CaseContactApiError(
      statusMessage(response.status),
      response.status,
    );
  }
}

function requireEntityTag(response: Response | undefined, version: number) {
  if (response?.headers.get("ETag") !== `"v${version}"`) {
    throw projectionMismatch();
  }
}

function statusMessage(status: number): string {
  switch (status) {
    case 400:
      return "The contact relationship request was not accepted.";
    case 401:
      return "Your session is no longer valid.";
    case 403:
      return "Your current access does not allow this Case contact action.";
    case 404:
      return "This Case, contact, or relationship is unavailable in the active tenant.";
    case 409:
      return "This contact relationship conflicts with current server state.";
    case 412:
    case 428:
      return "The Case or contact relationship changed. Reload the current snapshot before retrying.";
    default:
      return "The Case contact relationship could not be updated.";
  }
}

function isCanonicalText(
  value: string,
  maximumBytes: number,
  optional = false,
): boolean {
  if (value === "") return optional;
  return (
    new TextEncoder().encode(value).length <= maximumBytes &&
    !hasGoTrimSpaceAtEdge(value) &&
    !hasControlCharacters(value) &&
    !hasBidiControlCharacters(value) &&
    !hasUnpairedSurrogate(value)
  );
}

function isCanonicalContactEmail(value: string): boolean {
  if (
    value !== value.toLowerCase() ||
    value !== value.trim() ||
    value.length < 3 ||
    value.length > 320 ||
    !/^[\x21-\x7e]+$/u.test(value) ||
    (value.match(/@/gu)?.length ?? 0) !== 1
  ) {
    return false;
  }
  const [local = "", domain = ""] = value.split("@");
  if (
    local.length < 1 ||
    local.length > 64 ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    !/^[a-z0-9!#$%&'*+\-/=?^_`{|}~.]+$/u.test(local)
  ) {
    return false;
  }
  const labels = domain.split(".");
  return (
    labels.length >= 2 &&
    labels.every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        !label.startsWith("-") &&
        !label.endsWith("-") &&
        /^[a-z0-9-]+$/u.test(label),
    )
  );
}

function isKnownTimezone(value: string): boolean {
  try {
    new Intl.DateTimeFormat("en", { timeZone: value }).format(0);
    return true;
  } catch {
    return false;
  }
}

function isSameOrLaterInstant(candidate: string, reference: string): boolean {
  const candidateInstant = parseRfc3339Instant(candidate);
  const referenceInstant = parseRfc3339Instant(reference);
  return (
    candidateInstant !== undefined &&
    referenceInstant !== undefined &&
    candidateInstant >= referenceInstant
  );
}

function assertUniqueContactLinks(links: readonly CaseContactLink[]): void {
  const contactIds = new Set<string>();
  for (const link of links) {
    if (contactIds.has(link.contactId)) throw projectionMismatch();
    contactIds.add(link.contactId);
  }
}

function validateSortedKeys(
  values: readonly string[],
  context: z.RefinementCtx,
): void {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) {
      context.addIssue({ code: "custom", message: "Non-canonical keys" });
      return;
    }
  }
}

function compareWindows(
  left: z.infer<typeof notificationWindowSchema>,
  right: z.infer<typeof notificationWindowSchema>,
): number {
  return (
    left.isoWeekday - right.isoWeekday ||
    left.startMinute - right.startMinute ||
    left.endMinute - right.endMinute
  );
}

function sameProvenance(
  left: TicketCustomerContactEscalationProvenance | undefined,
  right: TicketCustomerContactEscalationProvenance | undefined,
): boolean {
  return left === undefined || right === undefined
    ? left === right
    : left.sourceAlertId === right.sourceAlertId &&
        left.sourceAlertVersion === right.sourceAlertVersion;
}

function isCaseContactRole(value: unknown): value is CaseContactRole {
  return value === "escalation" || value === "primary" || value === "watcher";
}

function hasNoStore(value: string | null): boolean {
  return (
    value
      ?.split(",")
      .some((directive) => directive.trim().toLowerCase() === "no-store") ??
    false
  );
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  const keys = Object.keys(value);
  const allowedKeys = new Set(allowed);
  return keys.every((key) => allowedKeys.has(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionMismatch(): CaseContactApiError {
  return new CaseContactApiError(
    "The Case contact response was not safe to apply.",
    undefined,
    "projection_mismatch",
  );
}
