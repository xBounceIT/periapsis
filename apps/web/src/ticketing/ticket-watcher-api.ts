import {
  addTenantAlertWatcher,
  addTenantCaseWatcher,
  getTenantAlertWatchers,
  getTenantCaseWatchers,
  removeTenantAlertWatcher,
  removeTenantCaseWatcher,
} from "@periapsis/contracts";
import { z } from "zod";

import { isCanonicalDisplayName } from "../lib/canonical-display-name";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";
import type { TicketKind } from "../lib/ticketing-api";

export interface TicketWatcherView {
  addedAt: string;
  displayName: string;
  userId: string;
}

export interface TicketWatcherPageView {
  items: readonly TicketWatcherView[];
  updatedAt: string;
  version: number;
}

export interface VersionedTicketWatcherPage {
  etag: string;
  value: TicketWatcherPageView;
}

export interface TicketWatcherMutationResult extends VersionedTicketWatcherPage {
  changed: boolean;
  replayed: boolean;
}

export interface TicketWatcherReadInput {
  kind: TicketKind;
  resourceId: string;
  signal?: AbortSignal;
  tenantId: string;
}

export interface TicketWatcherMutationInput extends TicketWatcherReadInput {
  action: "add" | "remove";
  csrfToken: string;
  etag: string;
  expectedVersion: number;
  idempotencyKey: string;
  userId: string;
}

export interface TicketWatcherApi {
  list(input: TicketWatcherReadInput): Promise<VersionedTicketWatcherPage>;
  mutate(
    input: TicketWatcherMutationInput,
  ): Promise<TicketWatcherMutationResult>;
}

export class TicketWatcherApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "TicketWatcherApiError";
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
export const watcherUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])/u;
const idempotencyKeyPattern = /^[A-Za-z0-9._~-]{16,128}(?![\s\S])/u;
const resourceVersionSchema = z.number().int().min(1).max(2_147_483_647);
const canonicalInstantSchema = z
  .string()
  .min(20)
  .max(30)
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/u)
  .refine((value) => parseRfc3339Instant(value) !== undefined);
const displayNameSchema = z.string().superRefine((value, context) => {
  if (!isCanonicalDisplayName(value, 160)) {
    context.addIssue({ code: "custom", message: "Invalid display name" });
  }
});
const watcherSchema = z
  .object({
    userId: z.string().regex(watcherUuidV7Pattern),
    displayName: displayNameSchema,
    addedAt: canonicalInstantSchema,
  })
  .strict();
const watcherPageSchema = z
  .object({
    items: z.array(watcherSchema).max(1000),
    version: resourceVersionSchema,
    updatedAt: canonicalInstantSchema,
  })
  .strict()
  .superRefine((page, context) => {
    const seen = new Set<string>();
    for (const [index, watcher] of page.items.entries()) {
      if (seen.has(watcher.userId)) {
        context.addIssue({ code: "custom", message: "Duplicate watcher" });
      }
      seen.add(watcher.userId);
      const previous = page.items[index - 1];
      if (previous && compareWatchers(previous, watcher) >= 0) {
        context.addIssue({ code: "custom", message: "Non-canonical order" });
      }
      const addedAt = parseRfc3339Instant(watcher.addedAt);
      const updatedAt = parseRfc3339Instant(page.updatedAt);
      if (
        addedAt !== undefined &&
        updatedAt !== undefined &&
        addedAt > updatedAt
      ) {
        context.addIssue({
          code: "custom",
          message: "Watcher added in the future",
        });
      }
    }
  });
const utf8 = new TextEncoder();

export const ticketWatcherApi: TicketWatcherApi = {
  async list(input) {
    requireCoordinates(input);
    let result: GeneratedResult;
    if (input.kind === "alert") {
      result = await getTenantAlertWatchers({
        ...sameOrigin,
        path: { alertId: input.resourceId, tenantId: input.tenantId },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    } else {
      result = await getTenantCaseWatchers({
        ...sameOrigin,
        path: { caseId: input.resourceId, tenantId: input.tenantId },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    }
    requireStatus(result.response, 200);
    const value = projectPage(result.data);
    return {
      etag: requireVersionEtag(result.response, value.version),
      value,
    };
  },

  async mutate(input) {
    requireMutationContext(input);
    const headers = {
      "Idempotency-Key": input.idempotencyKey,
      "If-Match": input.etag,
      "X-CSRF-Token": input.csrfToken,
    };
    let result: GeneratedResult;
    if (input.kind === "alert" && input.action === "add") {
      result = await addTenantAlertWatcher({
        ...sameOrigin,
        headers,
        path: {
          alertId: input.resourceId,
          tenantId: input.tenantId,
          userId: input.userId,
        },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    } else if (input.kind === "alert") {
      result = await removeTenantAlertWatcher({
        ...sameOrigin,
        headers,
        path: {
          alertId: input.resourceId,
          tenantId: input.tenantId,
          userId: input.userId,
        },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    } else if (input.action === "add") {
      result = await addTenantCaseWatcher({
        ...sameOrigin,
        headers,
        path: {
          caseId: input.resourceId,
          tenantId: input.tenantId,
          userId: input.userId,
        },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    } else {
      result = await removeTenantCaseWatcher({
        ...sameOrigin,
        headers,
        path: {
          caseId: input.resourceId,
          tenantId: input.tenantId,
          userId: input.userId,
        },
        ...(input.signal ? { signal: input.signal } : {}),
      });
    }

    requireStatus(result.response, 200);
    const value = projectPage(result.data);
    if (
      (value.version !== input.expectedVersion &&
        value.version !== input.expectedVersion + 1) ||
      (input.action === "add" &&
        !value.items.some((watcher) => watcher.userId === input.userId)) ||
      (input.action === "remove" &&
        value.items.some((watcher) => watcher.userId === input.userId))
    ) {
      throw projectionMismatch();
    }
    return {
      changed: value.version === input.expectedVersion + 1,
      etag: requireVersionEtag(result.response, value.version),
      replayed: requireReplayHeader(result.response),
      value,
    };
  },
};

function projectPage(source: unknown): TicketWatcherPageView {
  const parsed = watcherPageSchema.safeParse(source);
  if (!parsed.success) throw projectionMismatch();
  return {
    items: parsed.data.items.map((watcher) => ({ ...watcher })),
    updatedAt: parsed.data.updatedAt,
    version: parsed.data.version,
  };
}

function compareWatchers(
  left: Pick<TicketWatcherView, "displayName" | "userId">,
  right: Pick<TicketWatcherView, "displayName" | "userId">,
): number {
  const displayNameOrder = compareBytes(
    utf8.encode(left.displayName),
    utf8.encode(right.displayName),
  );
  if (displayNameOrder !== 0) return displayNameOrder;
  return left.userId < right.userId ? -1 : left.userId === right.userId ? 0 : 1;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = left[index]! - right[index]!;
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function requireCoordinates(input: TicketWatcherReadInput): void {
  if (
    !watcherUuidV7Pattern.test(input.tenantId) ||
    !watcherUuidV7Pattern.test(input.resourceId)
  ) {
    throw new TypeError(
      "Canonical tenant and ticket UUIDv7 values are required.",
    );
  }
}

function requireMutationContext(input: TicketWatcherMutationInput): void {
  requireCoordinates(input);
  if (!watcherUuidV7Pattern.test(input.userId)) {
    throw new TypeError("A canonical operator UUIDv7 is required.");
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
    input.csrfToken.trim() === "" ||
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
    throw new TicketWatcherApiError(
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

function requireReplayHeader(response: Response | undefined): boolean {
  const replayed = response?.headers.get("X-Idempotent-Replay");
  if (replayed !== "true" && replayed !== "false") throw projectionMismatch();
  return replayed === "true";
}

function statusMessage(status: number): string {
  switch (status) {
    case 401:
      return "Your session is no longer valid.";
    case 403:
      return "Your current access does not allow this watcher action.";
    case 404:
      return "This ticket or operator is not available in the active tenant.";
    case 409:
      return "This watcher action conflicts with current ticket state.";
    case 412:
    case 428:
      return "The watcher list changed. Reload the latest snapshot before retrying.";
    default:
      return "The watcher list could not be updated.";
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

function projectionMismatch(): TicketWatcherApiError {
  return new TicketWatcherApiError(
    "The watcher response was not safe to apply.",
  );
}
