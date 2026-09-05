import {
  getTenantTicketNumberingPolicy,
  previewTenantTicketNumberingPolicy,
  updateTenantTicketNumberingPolicy,
  type TicketNumberingMutationResult,
  type TicketNumberingPolicy,
  type TicketNumberingPreview,
} from "@periapsis/contracts";

import { PhaseTwoApiError } from "../../lib/phase-two-types";
import { parseRfc3339Instant } from "../../lib/rfc3339-instant";
import { sessionAwareFetch } from "../../lib/session-transition-transport";
import { isCanonicalUuidV7 } from "../../lib/uuid-v7";
import {
  entityTagVersion,
  isTicketNumberingDraft,
  isTicketNumberingMutationProjection,
  isTicketNumberingPolicyProjection,
  isTicketNumberingPreviewProjection,
  ticketNumberingReasonIsValid,
  ticketNumberingUpdateRequest,
  type TicketNumberingApi,
  type TicketNumberingUpdateResult,
  type VersionedTicketNumberingPolicy,
} from "./model";

interface GeneratedResult<T> {
  data: T | undefined;
  error?: unknown;
  response?: Response;
}

interface SafeProblem {
  code?: string;
}

const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}$/u;

export const ticketNumberingApi: TicketNumberingApi = {
  async get(tenantId, kind, signal) {
    requireContext(tenantId, kind);
    const result = await getTenantTicketNumberingPolicy({
      ...requestDefaults(),
      cache: "no-store",
      path: { kind, tenantId },
      ...(signal ? { signal } : {}),
    });
    return unwrapPolicy(result, tenantId, kind);
  },

  async preview(csrfToken, tenantId, kind, draft, signal) {
    requireContext(tenantId, kind);
    requireCsrf(csrfToken);
    if (!isTicketNumberingDraft(draft)) {
      throw new PhaseTwoApiError("The ticket numbering preview is invalid.");
    }
    const result = await previewTenantTicketNumberingPolicy({
      ...requestDefaults(),
      body: { ...draft },
      cache: "no-store",
      headers: { "X-CSRF-Token": csrfToken },
      path: { kind, tenantId },
      ...(signal ? { signal } : {}),
    });
    return unwrapPreview(result, tenantId, kind, draft);
  },

  async update(
    csrfToken,
    tenantId,
    kind,
    current,
    idempotencyKey,
    reason,
    draft,
    signal,
  ) {
    requireContext(tenantId, kind);
    requireCsrf(csrfToken);
    if (
      current.value.tenantId !== tenantId ||
      current.value.kind !== kind ||
      !isTicketNumberingPolicyProjection(current.value, tenantId, kind) ||
      entityTagVersion(current.etag) !== current.value.version ||
      !idempotencyKeyPattern.test(idempotencyKey) ||
      !ticketNumberingReasonIsValid(reason) ||
      !isTicketNumberingDraft(draft)
    ) {
      throw new PhaseTwoApiError("The ticket numbering command is invalid.");
    }
    const body = ticketNumberingUpdateRequest(current.value.version, draft);
    const result = await updateTenantTicketNumberingPolicy({
      ...requestDefaults(),
      body,
      cache: "no-store",
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": current.etag,
        "X-Audit-Reason": reason,
        "X-CSRF-Token": csrfToken,
      },
      path: { kind, tenantId },
      ...(signal ? { signal } : {}),
    });
    return unwrapMutation(result, tenantId, kind, current, draft);
  },
};

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function unwrapPolicy(
  result: GeneratedResult<TicketNumberingPolicy>,
  tenantId: string,
  kind: "alert" | "case",
): VersionedTicketNumberingPolicy {
  if (!result.response?.ok || result.response.status !== 200) {
    throw apiError(result.error, result.response, "load");
  }
  requirePrivateNoStore(result.response);
  if (!isTicketNumberingPolicyProjection(result.data, tenantId, kind)) {
    throw projectionError();
  }
  const etag = result.response.headers.get("ETag");
  if (!etag || entityTagVersion(etag) !== result.data.version) {
    throw projectionError();
  }
  return {
    etag,
    value: { ...result.data, publisher: { ...result.data.publisher } },
  };
}

function unwrapPreview(
  result: GeneratedResult<TicketNumberingPreview>,
  tenantId: string,
  kind: "alert" | "case",
  draft: Parameters<TicketNumberingApi["preview"]>[3],
): TicketNumberingPreview {
  if (!result.response?.ok || result.response.status !== 200) {
    throw apiError(result.error, result.response, "preview");
  }
  requirePrivateNoStore(result.response);
  if (!isTicketNumberingPreviewProjection(result.data, tenantId, kind, draft)) {
    throw projectionError();
  }
  return { ...result.data };
}

function unwrapMutation(
  result: GeneratedResult<TicketNumberingMutationResult>,
  tenantId: string,
  kind: "alert" | "case",
  current: VersionedTicketNumberingPolicy,
  draft: Parameters<TicketNumberingApi["update"]>[6],
): TicketNumberingUpdateResult {
  if (!result.response?.ok || result.response.status !== 200) {
    throw apiError(result.error, result.response, "update");
  }
  requirePrivateNoStore(result.response);
  if (!isTicketNumberingMutationProjection(result.data, tenantId, kind)) {
    throw projectionError();
  }
  const { policy, replayed } = result.data;
  const etag = result.response.headers.get("ETag");
  const replayHeader = result.response.headers.get("X-Idempotent-Replay");
  const currentPublishedAt = parseRfc3339Instant(current.value.publishedAt);
  const publishedAt = parseRfc3339Instant(policy.publishedAt);
  if (
    !etag ||
    entityTagVersion(etag) !== policy.version ||
    replayHeader !== String(replayed) ||
    policy.version !== current.value.version + 1 ||
    policy.versionId === current.value.versionId ||
    currentPublishedAt === undefined ||
    publishedAt === undefined ||
    publishedAt < currentPublishedAt ||
    policy.prefix !== draft.prefix ||
    policy.separator !== draft.separator ||
    policy.period !== draft.period ||
    policy.width !== draft.width ||
    policy.start !== draft.start
  ) {
    throw projectionError();
  }
  return {
    etag,
    replayed,
    value: { ...policy, publisher: { ...policy.publisher } },
  };
}

function requirePrivateNoStore(response: Response): void {
  const directives = response.headers
    .get("Cache-Control")
    ?.split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (!directives?.includes("private") || !directives.includes("no-store")) {
    throw new PhaseTwoApiError(
      "The API did not mark ticket numbering as private and no-store.",
      response.status,
    );
  }
}

function requireContext(tenantId: string, kind: string): void {
  if (!isCanonicalUuidV7(tenantId) || (kind !== "alert" && kind !== "case")) {
    throw new PhaseTwoApiError("The ticket numbering context is invalid.");
  }
}

function requireCsrf(csrfToken: string): void {
  if (
    csrfToken.length < 1 ||
    csrfToken.length > 128 ||
    csrfToken.trim() !== csrfToken ||
    csrfToken.includes(",")
  ) {
    throw new PhaseTwoApiError("The ticket numbering CSRF context is invalid.");
  }
}

function projectionError(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API response did not match the requested ticket numbering projection.",
    undefined,
    { code: "ticket_numbering_projection_mismatch" },
  );
}

function apiError(
  error: unknown,
  response: Response | undefined,
  operation: "load" | "preview" | "update",
): PhaseTwoApiError {
  const problem = safeProblem(error);
  const status = response?.status;
  const fallback =
    status === 412
      ? "This numbering policy changed after the form was loaded."
      : status === 409
        ? "This numbering policy conflicts with the current immutable history."
        : status === 403
          ? "The server denied access to ticket numbering."
          : status === 401
            ? "The current session is no longer authenticated."
            : operation === "preview"
              ? "The numbering preview could not be generated."
              : operation === "update"
                ? "The numbering policy could not be published."
                : "The numbering policy could not be loaded.";
  return new PhaseTwoApiError(
    fallback,
    status,
    problem?.code ? { code: problem.code } : undefined,
  );
}

function safeProblem(value: unknown): SafeProblem | null {
  if (
    value === null ||
    typeof value !== "object" ||
    !("code" in value) ||
    typeof value.code !== "string" ||
    !/^[a-z][a-z0-9_]{0,63}$/u.test(value.code)
  ) {
    return null;
  }
  return { code: value.code };
}
