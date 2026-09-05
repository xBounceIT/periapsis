import type {
  SavedTicketView,
  SavedTicketViewColumn,
  SavedTicketViewColumnInput,
  SavedTicketViewCoreColumnKey,
  SavedTicketViewSpec,
  SavedTicketViewSpecInput,
  TicketSort,
} from "@periapsis/contracts";

import type { TicketListFilters } from "../lib/ticketing-api";

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const savedViewURLKey = "view";

export type SavedViewURLSelection =
  { kind: "invalid" } | { kind: "none" } | { kind: "selected"; viewId: string };

export interface TicketTableColumnSpec {
  coreKey?: SavedTicketViewCoreColumnKey;
  definitionId?: string;
  definitionKey?: string;
  expectedDefinitionVersion?: number;
  pin: "end" | "none" | "start";
  source: "core" | "custom_field" | "sla";
  storedWidth?: number;
  visible: boolean;
  width: number;
}

export interface SavedViewAttempt {
  fingerprint: string;
  intent: string;
  key: string;
}

export const defaultTicketTableColumns: readonly TicketTableColumnSpec[] = [
  coreColumn("ticket", 360, true, "start"),
  coreColumn("state", 190, true),
  coreColumn("risk", 180, true),
  coreColumn("assignment", 230, true),
  coreColumn("category", 180, false),
  coreColumn("source", 180, false),
  coreColumn("customer_visibility", 180, false),
  coreColumn("created", 200, false),
  coreColumn("updated", 200, true),
];

export function parseSavedViewURL(
  parameters: URLSearchParams,
): SavedViewURLSelection {
  const values = parameters.getAll(savedViewURLKey);
  if (values.length === 0) return { kind: "none" };
  if (
    values.length !== 1 ||
    !uuidV7Pattern.test(values[0]!) ||
    [...parameters.keys()].some((key) => key !== savedViewURLKey)
  ) {
    return { kind: "invalid" };
  }
  return { kind: "selected", viewId: values[0]! };
}

export function savedViewURL(viewId?: string): URLSearchParams {
  const parameters = new URLSearchParams();
  if (viewId !== undefined) {
    if (!uuidV7Pattern.test(viewId)) {
      throw new TypeError("A canonical saved-view identifier is required.");
    }
    parameters.set(savedViewURLKey, viewId);
  }
  return parameters;
}

export function tableColumnsFromSavedView(
  columns: readonly SavedTicketViewColumn[],
): TicketTableColumnSpec[] {
  return columns.map((column) =>
    column.source === "core"
      ? {
          source: "core",
          coreKey: column.coreKey!,
          pin: column.pin,
          storedWidth: column.width,
          visible: column.visible,
          width: normalizedWidth(column.width, column.coreKey),
        }
      : {
          source: column.source,
          definitionId: column.definition!.id,
          definitionKey: column.definition!.key,
          expectedDefinitionVersion: column.definition!.version,
          pin: column.pin,
          storedWidth: column.width,
          visible: column.visible,
          width: normalizedWidth(column.width),
        },
  );
}

export function savedViewColumnsFromTable(
  columns: readonly TicketTableColumnSpec[],
): SavedTicketViewColumnInput[] {
  return columns.map((column) => {
    const persistedWidth = column.storedWidth ?? column.width;
    return column.source === "core"
      ? {
          source: "core",
          coreKey: column.coreKey!,
          pin: column.pin,
          visible: column.visible,
          ...(persistedWidth === 0
            ? {}
            : { width: normalizedWidth(persistedWidth, column.coreKey) }),
        }
      : {
          source: column.source,
          definitionId: column.definitionId!,
          expectedDefinitionVersion: column.expectedDefinitionVersion!,
          pin: column.pin,
          visible: column.visible,
          ...(persistedWidth === 0
            ? {}
            : { width: normalizedWidth(persistedWidth) }),
        };
  });
}

export function savedViewSpecInput(
  spec: SavedTicketViewSpec,
  columns: readonly TicketTableColumnSpec[],
): SavedTicketViewSpecInput {
  return {
    filters: {
      states: [...spec.filters.states],
      severities: [...spec.filters.severities],
      priorities: [...spec.filters.priorities],
      queue: spec.filters.queue,
      custom: spec.filters.custom.map((filter) => ({
        definitionId: filter.definition.id,
        expectedDefinitionVersion: filter.definition.version,
        operator: "equal",
        value: filter.value,
      })),
      ...(spec.filters.assignedTeamId
        ? { assignedTeamId: spec.filters.assignedTeamId }
        : {}),
      ...(spec.filters.assigneeUserId
        ? { assigneeUserId: spec.filters.assigneeUserId }
        : {}),
      ...(spec.filters.claimedBy ? { claimedBy: spec.filters.claimedBy } : {}),
      ...(spec.filters.customerVisible === undefined
        ? {}
        : { customerVisible: spec.filters.customerVisible }),
      ...(spec.filters.search ? { search: spec.filters.search } : {}),
    },
    sort:
      spec.sort.source === "core"
        ? {
            source: "core",
            coreKey: spec.sort.coreKey!,
            direction: spec.sort.direction,
            nulls: "last",
          }
        : {
            source: spec.sort.source,
            definitionId: spec.sort.definition!.id,
            expectedDefinitionVersion: spec.sort.definition!.version,
            direction: spec.sort.direction,
            nulls: spec.sort.nulls,
          },
    columns: savedViewColumnsFromTable(columns),
  };
}

export function inlineSavedViewSpec(
  filters: TicketListFilters,
  columns: readonly TicketTableColumnSpec[],
): SavedTicketViewSpecInput {
  if (filters.viewId !== undefined || filters.after !== undefined) {
    throw new TypeError(
      "Cursor and saved-view identity are not persistable filters.",
    );
  }
  return {
    filters: {
      states: [...(filters.status ?? [])],
      severities: [...(filters.severity ?? [])],
      priorities: [...(filters.priority ?? [])],
      queue: filters.queue ?? "all",
      custom: [],
      ...(filters.customerVisible === undefined
        ? {}
        : { customerVisible: filters.customerVisible }),
      ...(filters.search ? { search: filters.search } : {}),
    },
    sort: coreSortInput(filters.sort ?? "updated_at_desc"),
    columns: savedViewColumnsFromTable(columns),
  };
}

export function acquireSavedViewAttempt(
  current: SavedViewAttempt | undefined,
  intent: string,
  payload: unknown,
): SavedViewAttempt {
  const fingerprint = canonicalAttemptFingerprint(payload);
  if (current?.intent === intent && current.fingerprint === fingerprint) {
    return current;
  }
  const secureCrypto = globalThis.crypto;
  if (typeof secureCrypto?.randomUUID !== "function") {
    throw new TypeError("Secure idempotency key generation is unavailable.");
  }
  return {
    fingerprint,
    intent,
    key: `saved-view-${secureCrypto.randomUUID()}`,
  };
}

export function savedViewColumnIdentity(column: TicketTableColumnSpec): string {
  return column.source === "core"
    ? `core:${column.coreKey!}`
    : `${column.source}:${column.definitionId!}`;
}

export function savedViewColumnLabel(column: TicketTableColumnSpec): string {
  if (column.source === "core") {
    return humanize(column.coreKey!);
  }
  return column.definitionKey
    ? humanize(column.definitionKey)
    : column.source === "sla"
      ? "SLA column"
      : "Custom field";
}

export function savedViewSelectionLabel(view: SavedTicketView): string {
  return view.status === "archived" ? `${view.name} (archived)` : view.name;
}

export function sameTableColumns(
  left: readonly TicketTableColumnSpec[],
  right: readonly TicketTableColumnSpec[],
): boolean {
  return (
    canonicalAttemptFingerprint(left) === canonicalAttemptFingerprint(right)
  );
}

function coreColumn(
  coreKey: SavedTicketViewCoreColumnKey,
  width: number,
  visible: boolean,
  pin: "end" | "none" | "start" = "none",
): TicketTableColumnSpec {
  return { source: "core", coreKey, pin, visible, width };
}

function coreSortInput(sort: TicketSort): SavedTicketViewSpecInput["sort"] {
  switch (sort) {
    case "updated_at_desc":
      return {
        source: "core",
        coreKey: "updated_at",
        direction: "desc",
        nulls: "last",
      };
    case "updated_at_asc":
      return {
        source: "core",
        coreKey: "updated_at",
        direction: "asc",
        nulls: "last",
      };
    case "created_at_desc":
      return {
        source: "core",
        coreKey: "created_at",
        direction: "desc",
        nulls: "last",
      };
    case "created_at_asc":
      return {
        source: "core",
        coreKey: "created_at",
        direction: "asc",
        nulls: "last",
      };
    case "priority_desc":
      return {
        source: "core",
        coreKey: "priority",
        direction: "desc",
        nulls: "last",
      };
    case "oldest_unclaimed":
      return {
        source: "core",
        coreKey: "oldest_unclaimed",
        direction: "asc",
        nulls: "last",
      };
    default:
      throw new TypeError("Unsupported ticket sort.");
  }
}

function normalizedWidth(
  width: number,
  coreKey?: SavedTicketViewCoreColumnKey,
): number {
  if (width >= 80 && width <= 1_200) return Math.round(width);
  return (
    defaultTicketTableColumns.find((column) => column.coreKey === coreKey)
      ?.width ?? 180
  );
}

function canonicalAttemptFingerprint(payload: unknown): string {
  return JSON.stringify(canonicalize(payload));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value)
      .toSorted(([left], [right]) => left.localeCompare(right, "en"))
      .map(([key, nested]) => [key, canonicalize(nested)]),
  );
}

function humanize(value: string): string {
  return value
    .replaceAll("_", " ")
    .replaceAll(".", " · ")
    .replace(/^./u, (letter) => letter.toUpperCase());
}
