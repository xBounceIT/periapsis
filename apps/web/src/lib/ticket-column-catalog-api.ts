import {
  listTenantCustomFieldDefinitions,
  listTenantSlaColumns,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "./session-transition-transport";

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const keyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const maximumSafeRevision = Number.MAX_SAFE_INTEGER;

export type TicketColumnCatalogKind = "alert" | "case";

export interface TicketDynamicColumnCatalogItem {
  definitionId: string;
  definitionKey: string;
  definitionLabel: string;
  definitionVersion: number;
  source: "custom_field" | "sla";
}

export interface TicketColumnCatalogPage {
  items: TicketDynamicColumnCatalogItem[];
  nextCursor?: string;
}

export interface TicketColumnCatalogApi {
  listCustomFields(input: {
    after?: string;
    kind: TicketColumnCatalogKind;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketColumnCatalogPage>;
  listSlaColumns(input: {
    after?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<TicketColumnCatalogPage>;
}

export class TicketColumnCatalogApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "TicketColumnCatalogApiError";
    this.status = status;
  }
}

export const ticketColumnCatalogApi: TicketColumnCatalogApi = {
  async listCustomFields({ after, kind, signal, tenantId }) {
    requireCoordinates(tenantId, kind);
    const result = await listTenantCustomFieldDefinitions({
      ...requestDefaults(),
      path: { tenantId },
      query: {
        objectType: kind,
        includeArchived: false,
        limit: 100,
        ...(after ? { after } : {}),
      },
      ...(signal ? { signal } : {}),
    });
    requireSuccess(result.response);
    const page = requireObject(result.data);
    const items = requireArray(readMember(page, "items"), 200);
    return {
      items: items
        .map((item) => projectCustomField(item, tenantId, kind))
        .filter(
          (item): item is TicketDynamicColumnCatalogItem => item !== undefined,
        ),
      ...projectCursor(readMember(page, "nextCursor")),
    };
  },

  async listSlaColumns({ after, signal, tenantId }) {
    requireCoordinates(tenantId);
    const result = await listTenantSlaColumns({
      ...requestDefaults(),
      path: { tenantId },
      query: {
        includeArchived: false,
        limit: 100,
        ...(after ? { after } : {}),
      },
      ...(signal ? { signal } : {}),
    });
    requireSuccess(result.response);
    const page = requireObject(result.data);
    if (readMember(page, "tenantId") !== tenantId) {
      throw projectionMismatch();
    }
    const items = requireArray(readMember(page, "items"), 100);
    return {
      items: items
        .map((item) => projectSlaColumn(item, tenantId))
        .filter(
          (item): item is TicketDynamicColumnCatalogItem => item !== undefined,
        ),
      ...projectCursor(readMember(page, "nextCursor")),
    };
  },
};

function projectCustomField(
  value: unknown,
  tenantId: string,
  kind: TicketColumnCatalogKind,
): TicketDynamicColumnCatalogItem | undefined {
  const item = requireObject(value);
  const definition = requireObject(readMember(item, "definition"));
  const placement = requireObject(readMember(definition, "placement"));
  const visibility = requireObject(readMember(definition, "visibility"));
  const id = readMember(item, "id");
  const schemaVersion = readMember(item, "schemaVersion");
  const key = readMember(definition, "key");
  const label = readMember(definition, "label");
  if (
    readMember(item, "tenantId") !== tenantId ||
    typeof id !== "string" ||
    !uuidV7Pattern.test(id) ||
    !validRevision(schemaVersion) ||
    readMember(item, "archived") !== false ||
    readMember(definition, "objectType") !== kind ||
    readMember(visibility, "operator") !== true ||
    readMember(placement, "showInList") !== true ||
    typeof key !== "string" ||
    typeof label !== "string"
  ) {
    return undefined;
  }
  return projectCatalogIdentity("custom_field", id, schemaVersion, key, label);
}

function projectSlaColumn(
  value: unknown,
  tenantId: string,
): TicketDynamicColumnCatalogItem | undefined {
  const item = requireObject(value);
  const id = readMember(item, "id");
  const version = readMember(item, "version");
  const key = readMember(item, "key");
  const label = readMember(item, "label");
  if (
    readMember(item, "tenantId") !== tenantId ||
    typeof id !== "string" ||
    !uuidV7Pattern.test(id) ||
    !validRevision(version) ||
    readMember(item, "archivedAt") !== undefined ||
    typeof key !== "string" ||
    typeof label !== "string"
  ) {
    return undefined;
  }
  return projectCatalogIdentity("sla", id, version, key, label);
}

function projectCatalogIdentity(
  source: TicketDynamicColumnCatalogItem["source"],
  definitionId: string,
  definitionVersion: number,
  definitionKey: string,
  definitionLabel: string,
): TicketDynamicColumnCatalogItem {
  if (
    !uuidV7Pattern.test(definitionId) ||
    !validRevision(definitionVersion) ||
    !keyPattern.test(definitionKey) ||
    !validLabel(definitionLabel)
  ) {
    throw projectionMismatch();
  }
  return {
    definitionId,
    definitionKey,
    definitionLabel,
    definitionVersion,
    source,
  };
}

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    cache: "no-store" as const,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function requireCoordinates(
  tenantId: string,
  kind?: TicketColumnCatalogKind,
): void {
  if (
    !uuidV7Pattern.test(tenantId) ||
    (kind !== undefined && kind !== "alert" && kind !== "case")
  ) {
    throw new TypeError(
      "Canonical ticket-column catalog coordinates are required.",
    );
  }
}

function requireSuccess(response: Response | undefined): void {
  if (response?.ok !== true || response.status !== 200) {
    throw new TicketColumnCatalogApiError(
      response?.status === 401
        ? "Your session is no longer valid."
        : response?.status === 403
          ? "Your current access does not include this column catalog."
          : "The ticket column catalog is temporarily unavailable.",
      response?.status,
    );
  }
  if (response.headers.get("Cache-Control") !== "no-store") {
    throw projectionMismatch();
  }
}

function requireObject(value: unknown): object {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw projectionMismatch();
  }
  return value;
}

function readMember(value: object, key: string): unknown {
  if (!Object.hasOwn(value, key)) return undefined;
  const member: unknown = Reflect.get(value, key);
  return member;
}

function requireArray(value: unknown, maximumLength: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximumLength) {
    throw projectionMismatch();
  }
  return Array.from(value, (item: unknown) => item);
}

function projectCursor(value: unknown): { nextCursor?: string } {
  if (value === undefined) return {};
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4096 ||
    value.trim() !== value ||
    containsControlCharacter(value)
  ) {
    throw projectionMismatch();
  }
  return { nextCursor: value };
}

function validRevision(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= maximumSafeRevision
  );
}

function validLabel(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 256 &&
    value.trim() === value &&
    !containsControlCharacter(value)
  );
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      return true;
    }
  }
  return false;
}

function projectionMismatch(): TicketColumnCatalogApiError {
  return new TicketColumnCatalogApiError(
    "The ticket column catalog response was not canonical.",
  );
}
