import {
  replaceTenantAlertMetadata,
  replaceTenantCaseMetadata,
  type AlertMetadataReplaceRequest,
  type AlertSeverity,
  type CaseMetadataReplaceRequest,
  type TicketPriority,
} from "@periapsis/contracts";
import { z } from "zod";

import { sessionAwareFetch } from "../lib/session-transition-transport";
import type { TicketKind } from "../lib/ticketing-api";
import {
  containsDisallowedMetadataControl,
  hasMetadataEdgeWhitespace,
  metadataCodePointLength,
  ticketMetadataTagPattern,
} from "./ticket-metadata-validation";

interface MetadataMutationContext {
  csrfToken: string;
  etag: string;
  expectedVersion: number;
  idempotencyKey: string;
  resourceId: string;
  signal?: AbortSignal;
  tenantId: string;
}

export type TicketMetadataReplaceInput = MetadataMutationContext &
  (
    | { body: AlertMetadataReplaceRequest; kind: "alert" }
    | { body: CaseMetadataReplaceRequest; kind: "case" }
  );

interface TicketMetadataBaseView {
  category: string;
  classification: string | null;
  customerVisible: boolean;
  description: string;
  id: string;
  priority: TicketPriority;
  severity: AlertSeverity;
  tags: string[];
  title: string;
  updatedAt: string;
  version: number;
}

export type TicketMetadataView =
  | (TicketMetadataBaseView & { kind: "alert" })
  | (TicketMetadataBaseView & { kind: "case"; summary: string });

export interface VersionedTicketMetadata {
  etag: string;
  value: TicketMetadataView;
}

export interface TicketMetadataApi {
  replace(input: TicketMetadataReplaceInput): Promise<VersionedTicketMetadata>;
}

export class TicketMetadataApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "TicketMetadataApiError";
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
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;
const severitySchema = z.enum([
  "informational",
  "low",
  "medium",
  "high",
  "critical",
]);
const prioritySchema = z.enum(["low", "medium", "high", "urgent", "critical"]);
const resourceVersionSchema = z.number().int().min(1).max(2_147_483_647);
const canonicalInstantSchema = z
  .string()
  .min(20)
  .max(35)
  .refine((value) => value.endsWith("Z") && !Number.isNaN(Date.parse(value)));

const canonicalText = (
  maximumCharacters: number,
  required: boolean,
  multiline = false,
) =>
  z.string().superRefine((value, context) => {
    if (
      (required && value.length === 0) ||
      hasMetadataEdgeWhitespace(value) ||
      metadataCodePointLength(value) > maximumCharacters ||
      containsDisallowedMetadataControl(value, multiline)
    ) {
      context.addIssue({ code: "custom", message: "Non-canonical text" });
    }
  });

const tagsSchema = z
  .array(z.string().regex(ticketMetadataTagPattern))
  .max(100)
  .superRefine((tags, context) => {
    if (
      new Set(tags).size !== tags.length ||
      tags.some((tag, index) => index > 0 && tags[index - 1]! > tag)
    ) {
      context.addIssue({ code: "custom", message: "Non-canonical tags" });
    }
  });

const metadataBaseSchema = z.strictObject({
  title: canonicalText(240, true),
  description: canonicalText(20_000, false, true),
  severity: severitySchema,
  priority: prioritySchema,
  category: canonicalText(120, true),
  classification: canonicalText(120, true).nullable(),
  customerVisible: z.boolean(),
  tags: tagsSchema,
});
const alertRequestSchema = metadataBaseSchema
  .extend({ description: canonicalText(10_000, false, true) })
  .strict();
const caseRequestSchema = metadataBaseSchema
  .extend({ summary: canonicalText(2_000, false, true) })
  .strict();
const alertResponseSchema = alertRequestSchema
  .extend({
    id: z.string().regex(uuidV7Pattern),
    version: resourceVersionSchema,
    updatedAt: canonicalInstantSchema,
  })
  .strict();
const caseResponseSchema = caseRequestSchema
  .extend({
    id: z.string().regex(uuidV7Pattern),
    version: resourceVersionSchema,
    updatedAt: canonicalInstantSchema,
  })
  .strict();

export const ticketMetadataApi: TicketMetadataApi = {
  async replace(input) {
    requireMutationContext(input);
    const headers = {
      "Idempotency-Key": input.idempotencyKey,
      "If-Match": input.etag,
      "X-CSRF-Token": input.csrfToken,
    };
    let result: GeneratedResult;
    let submitted: AlertMetadataReplaceRequest | CaseMetadataReplaceRequest;
    if (input.kind === "alert") {
      const body = alertRequestSchema.parse(input.body);
      submitted = body;
      result = await replaceTenantAlertMetadata({
        ...sameOrigin,
        body,
        headers,
        path: { alertId: input.resourceId, tenantId: input.tenantId },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    } else {
      const body = caseRequestSchema.parse(input.body);
      submitted = body;
      result = await replaceTenantCaseMetadata({
        ...sameOrigin,
        body,
        headers,
        path: { caseId: input.resourceId, tenantId: input.tenantId },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    }
    requireStatus(result.response, 200);
    const projected = projectMetadata(
      input.kind,
      result.data,
      input.resourceId,
      input.expectedVersion,
      submitted,
    );
    return {
      etag: requireVersionEtag(result.response, projected.version),
      value: projected,
    };
  },
};

function projectMetadata(
  kind: TicketKind,
  source: unknown,
  resourceId: string,
  expectedVersion: number,
  submitted: AlertMetadataReplaceRequest | CaseMetadataReplaceRequest,
): TicketMetadataView {
  if (kind === "alert") {
    const parsed = alertResponseSchema.safeParse(source);
    if (!parsed.success) throw projectionMismatch();
    const value = parsed.data;
    if (
      value.id !== resourceId ||
      value.version !== expectedVersion + 1 ||
      !sameMetadata(value, submitted, false)
    ) {
      throw projectionMismatch();
    }
    return { kind, ...value, tags: [...value.tags] };
  }
  const parsed = caseResponseSchema.safeParse(source);
  if (!parsed.success) throw projectionMismatch();
  const value = parsed.data;
  if (
    value.id !== resourceId ||
    value.version !== expectedVersion + 1 ||
    !sameMetadata(value, submitted, true)
  ) {
    throw projectionMismatch();
  }
  return { kind, ...value, tags: [...value.tags] };
}

function sameMetadata(
  value: z.infer<typeof alertResponseSchema | typeof caseResponseSchema>,
  submitted: AlertMetadataReplaceRequest | CaseMetadataReplaceRequest,
  includeSummary: boolean,
): boolean {
  return (
    value.title === submitted.title &&
    value.description === submitted.description &&
    value.severity === submitted.severity &&
    value.priority === submitted.priority &&
    value.category === submitted.category &&
    value.classification === submitted.classification &&
    value.customerVisible === submitted.customerVisible &&
    value.tags.length === submitted.tags.length &&
    value.tags.every((tag, index) => tag === submitted.tags[index]) &&
    (!includeSummary ||
      ("summary" in value &&
        "summary" in submitted &&
        value.summary === submitted.summary))
  );
}

function requireMutationContext(input: TicketMetadataReplaceInput): void {
  if (
    !uuidV7Pattern.test(input.tenantId) ||
    !uuidV7Pattern.test(input.resourceId)
  ) {
    throw new TypeError(
      "Canonical tenant and ticket UUIDv7 values are required.",
    );
  }
  if (
    !Number.isSafeInteger(input.expectedVersion) ||
    input.expectedVersion < 1 ||
    input.expectedVersion >= 2_147_483_647 ||
    input.etag !== `"v${input.expectedVersion}"`
  ) {
    throw new TypeError("The exact current ticket version is required.");
  }
  if (
    !input.csrfToken ||
    containsAnyControl(input.csrfToken) ||
    !idempotencyKeyPattern.test(input.idempotencyKey)
  ) {
    throw new TypeError("Canonical mutation credentials are required.");
  }
}

function requireStatus(response: Response | undefined, status: number): void {
  if (response?.headers.get("Cache-Control") !== "no-store") {
    throw projectionMismatch();
  }
  if (response.status !== status) {
    throw new TicketMetadataApiError(
      statusMessage(response.status),
      response.status,
    );
  }
}

function requireVersionEtag(
  response: Response | undefined,
  version: number,
): string {
  const etag = response?.headers.get("ETag") ?? "";
  if (etag !== `"v${version}"`) throw projectionMismatch();
  return etag;
}

function statusMessage(status: number): string {
  switch (status) {
    case 401:
      return "Your session is no longer valid.";
    case 403:
      return "Your current access does not allow core detail changes.";
    case 404:
      return "This ticket is no longer available in the active tenant.";
    case 409:
      return "This replacement conflicts with current ticket state.";
    case 412:
    case 428:
      return "This ticket changed. Reload the latest snapshot before retrying.";
    default:
      return "Core ticket details could not be saved.";
  }
}

function containsAnyControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 0x1f || codePoint === 0x7f)) {
      return true;
    }
  }
  return false;
}

function projectionMismatch(): TicketMetadataApiError {
  return new TicketMetadataApiError(
    "The core-detail response was not safe to apply.",
  );
}
