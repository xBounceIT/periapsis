import { isCanonicalUuidV7 } from "../lib/uuid-v7";
import type { CustomFieldObjectType } from "./model";

export const customFieldImportRouteDescriptor = {
  path: "/tenant/custom-field-imports",
  label: "Custom-field imports",
} as const;

export const customFieldImportMaximumRows = 10_000;
export const customFieldImportMaximumFieldsPerRow = 512;
export const customFieldImportMaximumCells = 100_000;
export const customFieldImportMaximumPayloadBytes = 32 * 1024 * 1024;
export const customFieldImportDefaultRetentionSeconds = 86_400;
export const customFieldImportMaximumExpectedVersion =
  Number.MAX_SAFE_INTEGER - 1;
export const customFieldImportMaximumRevision = 2_147_483_646;

export type CustomFieldImportMode = "dry_run" | "commit";
export type CustomFieldImportJobState =
  | "pending"
  | "running"
  | "cancellation_requested"
  | "completed"
  | "failed"
  | "cancelled"
  | "authorization_revoked"
  | "expired";

export type CustomFieldImportOutcome =
  | "dry_run_valid"
  | "committed"
  | "no_change"
  | "validation_failed"
  | "definition_changed"
  | "version_conflict"
  | "not_found_or_hidden"
  | "authorization_denied"
  | "cancelled"
  | "authorization_revoked"
  | "expired"
  | "internal_failure";

export interface CustomFieldImportFieldRequest {
  key: string;
  value?: unknown;
}

export interface CustomFieldImportRowRequest {
  targetId: string;
  expectedVersion: number;
  fields: CustomFieldImportFieldRequest[];
}

export interface CustomFieldImportRequest {
  objectType: CustomFieldObjectType;
  mode: CustomFieldImportMode;
  rows: CustomFieldImportRowRequest[];
  retentionSeconds: number;
}

export interface CustomFieldImportProgress {
  total: number;
  processed: number;
  succeeded: number;
  noChange: number;
  versionConflict: number;
  notFoundOrHidden: number;
  authorizationDenied: number;
  rejected: number;
  cancelled: number;
  authorizationRevoked: number;
  expired: number;
  internalFailure: number;
}

export interface CustomFieldImportJobView {
  id: string;
  tenantId: string;
  requesterUserId: string;
  ownerMembershipId: string;
  objectType: CustomFieldObjectType;
  mode: CustomFieldImportMode;
  state: CustomFieldImportJobState;
  revision: number;
  attempts: number;
  progress: CustomFieldImportProgress;
  requestedAt: string;
  updatedAt: string;
  availableAt: string;
  expiresAt: string;
  terminalAt?: string;
  activeAttempt: boolean;
}

export interface CustomFieldImportMutationView {
  job: CustomFieldImportJobView;
  replayed: boolean;
  etag: string;
}

export interface CustomFieldImportFieldErrorView {
  field: string;
  code: string;
}

export interface CustomFieldImportResultView {
  sequence: number;
  targetId: string;
  expectedVersion: number;
  outcome: CustomFieldImportOutcome;
  resultingVersion: number;
  fieldErrors: CustomFieldImportFieldErrorView[];
  recordedAt: string;
}

export interface CustomFieldImportResultPageView {
  items: CustomFieldImportResultView[];
  nextAfter?: number;
}

export interface CustomFieldImportDraftSummary {
  emptyValues: number;
  fields: number;
  missingValues: number;
  nullValues: number;
  rows: number;
}

export interface ParsedCustomFieldImportRows {
  rows: CustomFieldImportRowRequest[];
  summary: CustomFieldImportDraftSummary;
}

const fieldKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/u;
const terminalStates: ReadonlySet<CustomFieldImportJobState> = new Set([
  "completed",
  "failed",
  "cancelled",
  "authorization_revoked",
  "expired",
]);

export const customFieldImportExample = `[
  {
    "targetId": "0198c97d-cf4f-7000-8000-000000000101",
    "expectedVersion": 7,
    "fields": [
      { "key": "triage.owner", "value": "incident-response" },
      { "key": "triage.note", "value": "" },
      { "key": "triage.reviewed_at", "value": null },
      { "key": "triage.preserve_existing" }
    ]
  }
]`;

export function parseCustomFieldImportRows(
  source: string,
): ParsedCustomFieldImportRows {
  const payloadBytes = new TextEncoder().encode(source).length;
  if (payloadBytes === 0) {
    throw new TypeError("Paste at least one import row.");
  }
  if (payloadBytes > customFieldImportMaximumPayloadBytes) {
    throw new TypeError("The import payload must not exceed 32 MiB.");
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(source) as unknown;
  } catch {
    throw new TypeError("Enter a valid JSON array of import rows.");
  }
  assertUniqueJsonObjectKeys(source);
  if (!Array.isArray(decoded) || decoded.length === 0) {
    throw new TypeError("The import must contain at least one row.");
  }
  if (decoded.length > customFieldImportMaximumRows) {
    throw new TypeError(
      `The import must contain at most ${customFieldImportMaximumRows.toLocaleString("en-US")} rows.`,
    );
  }

  const targets = new Set<string>();
  let fields = 0;
  let missingValues = 0;
  let nullValues = 0;
  let emptyValues = 0;
  const rows = decoded.map((value, index) => {
    const rowNumber = index + 1;
    const row = requireExactRecord(
      value,
      ["targetId", "expectedVersion", "fields"],
      `Row ${rowNumber}`,
    );
    if (!isCanonicalUuidV7(row["targetId"])) {
      throw new TypeError(
        `Row ${rowNumber} needs a canonical UUIDv7 targetId.`,
      );
    }
    const targetId = row["targetId"];
    if (targets.has(targetId)) {
      throw new TypeError(`Row ${rowNumber} repeats targetId ${targetId}.`);
    }
    targets.add(targetId);
    const expectedVersion = row["expectedVersion"];
    if (!isResourceVersion(expectedVersion)) {
      throw new TypeError(
        `Row ${rowNumber} needs a positive, safe expectedVersion.`,
      );
    }
    const rawFields = row["fields"];
    if (!Array.isArray(rawFields)) {
      throw new TypeError(`Row ${rowNumber} fields must be an array.`);
    }
    if (rawFields.length > customFieldImportMaximumFieldsPerRow) {
      throw new TypeError(
        `Row ${rowNumber} must contain at most ${customFieldImportMaximumFieldsPerRow} fields.`,
      );
    }
    fields += rawFields.length;
    if (fields > customFieldImportMaximumCells) {
      throw new TypeError(
        `The import must contain at most ${customFieldImportMaximumCells.toLocaleString("en-US")} fields.`,
      );
    }
    const keys = new Set<string>();
    const projectedFields = rawFields.map((fieldValue, fieldIndex) => {
      const label = `Row ${rowNumber}, field ${fieldIndex + 1}`;
      const field = requireFieldRecord(fieldValue, label);
      const key = field["key"];
      if (typeof key !== "string" || !fieldKeyPattern.test(key)) {
        throw new TypeError(`${label} needs a canonical custom-field key.`);
      }
      if (keys.has(key)) {
        throw new TypeError(`Row ${rowNumber} repeats field key ${key}.`);
      }
      keys.add(key);
      if (!Object.hasOwn(field, "value")) {
        missingValues += 1;
        return { key };
      }
      const fieldData = field["value"];
      requireImportCellValue(fieldData, `${label} value`);
      if (fieldData === null) nullValues += 1;
      if (fieldData === "") emptyValues += 1;
      return { key, value: fieldData };
    });
    return { targetId, expectedVersion, fields: projectedFields };
  });

  return {
    rows,
    summary: {
      rows: rows.length,
      fields,
      missingValues,
      nullValues,
      emptyValues,
    },
  };
}

export function buildCustomFieldImportRequest(input: {
  mode: CustomFieldImportMode;
  objectType: CustomFieldObjectType;
  retentionSeconds: number;
  rows: CustomFieldImportRowRequest[];
}): CustomFieldImportRequest {
  if (input.mode !== "dry_run" && input.mode !== "commit") {
    throw new TypeError("Choose dry run or commit mode.");
  }
  if (input.objectType !== "alert" && input.objectType !== "case") {
    throw new TypeError("Choose Alert or Case imports.");
  }
  if (
    !Number.isSafeInteger(input.retentionSeconds) ||
    input.retentionSeconds < 300 ||
    input.retentionSeconds > 2_592_000
  ) {
    throw new TypeError(
      "Receipt retention must be between 5 minutes and 30 days.",
    );
  }
  requireDirectJsonRows(input.rows);
  let encodedRows: string;
  try {
    encodedRows = JSON.stringify(input.rows);
  } catch {
    throw new TypeError("Import rows must be JSON serializable.");
  }
  const rows = parseCustomFieldImportRows(encodedRows).rows;
  const request: CustomFieldImportRequest = {
    objectType: input.objectType,
    mode: input.mode,
    rows,
    retentionSeconds: input.retentionSeconds,
  };
  if (
    new TextEncoder().encode(JSON.stringify(request)).length >
    customFieldImportMaximumPayloadBytes
  ) {
    throw new TypeError("The import request must not exceed 32 MiB.");
  }
  return request;
}

export function isCustomFieldImportTerminal(
  state: CustomFieldImportJobState,
): boolean {
  return terminalStates.has(state);
}

export function humanizeCustomFieldImportKey(value: string): string {
  return value
    .split("_")
    .map((part) => (part ? part[0]!.toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function requireFieldRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) throw new TypeError(`${label} must be an object.`);
  const keys = Object.keys(value);
  if (
    !keys.includes("key") ||
    keys.some((key) => key !== "key" && key !== "value")
  ) {
    throw new TypeError(`${label} may contain only key and optional value.`);
  }
  return value;
}

function requireExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) throw new TypeError(`${label} must be an object.`);
  const actualKeys = Object.keys(value);
  const allowedKeys = new Set(expectedKeys);
  if (
    actualKeys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(value, key)) ||
    actualKeys.some((key) => !allowedKeys.has(key))
  ) {
    throw new TypeError(`${label} has unsupported or missing properties.`);
  }
  return value;
}

function requireSafeJsonValue(value: unknown, label: string, depth = 0): void {
  requireSafeJsonValueWithBudget(value, label, depth, { remaining: 4_096 });
}

function requireSafeJsonValueWithBudget(
  value: unknown,
  label: string,
  depth: number,
  budget: { remaining: number },
): void {
  if (depth > 32) throw new TypeError(`${label} is nested too deeply.`);
  budget.remaining -= 1;
  if (budget.remaining < 0) {
    throw new TypeError(`${label} contains too many JSON values.`);
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new TypeError(
        `${label} contains a number that cannot be sent safely.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      requireSafeJsonValueWithBudget(item, label, depth + 1, budget);
    }
    return;
  }
  if (isRecord(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (hasControlCharacter(key)) {
        throw new TypeError(`${label} contains an unsafe object key.`);
      }
      requireSafeJsonValueWithBudget(item, label, depth + 1, budget);
    }
    return;
  }
  throw new TypeError(`${label} is not JSON serializable.`);
}

function requireImportCellValue(value: unknown, label: string): void {
  requireSafeJsonValue(value, label);
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new TypeError(`${label} is not JSON serializable.`);
  }
  if (new TextEncoder().encode(encoded).length > 65_536) {
    throw new TypeError(`${label} must not exceed 64 KiB.`);
  }
}

function requireDirectJsonRows(rows: unknown): void {
  if (
    !Array.isArray(rows) ||
    rows.length === 0 ||
    rows.length > customFieldImportMaximumRows
  ) {
    throw new TypeError("A bounded set of import rows is required.");
  }
  let fieldCount = 0;
  for (const [rowIndex, value] of rows.entries()) {
    const row = requireExactRecord(
      value,
      ["targetId", "expectedVersion", "fields"],
      `Row ${rowIndex + 1}`,
    );
    if (!Array.isArray(row["fields"])) {
      throw new TypeError(`Row ${rowIndex + 1} fields must be an array.`);
    }
    if (row["fields"].length > customFieldImportMaximumFieldsPerRow) {
      throw new TypeError(
        `Row ${rowIndex + 1} must contain at most ${customFieldImportMaximumFieldsPerRow} fields.`,
      );
    }
    fieldCount += row["fields"].length;
    if (fieldCount > customFieldImportMaximumCells) {
      throw new TypeError(
        `The import must contain at most ${customFieldImportMaximumCells.toLocaleString("en-US")} fields.`,
      );
    }
    for (const [fieldIndex, fieldValue] of row["fields"].entries()) {
      const label = `Row ${rowIndex + 1}, field ${fieldIndex + 1}`;
      const field = requireFieldRecord(fieldValue, label);
      if (Object.hasOwn(field, "value")) {
        requireImportCellValue(field["value"], `${label} value`);
      }
    }
  }
}

function isResourceVersion(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    Number(value) > 0 &&
    Number(value) <= customFieldImportMaximumExpectedVersion
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const point = character.codePointAt(0);
    if (
      point !== undefined &&
      (point <= 0x1f ||
        (point >= 0x7f && point <= 0x9f) ||
        (point >= 0x202a && point <= 0x202e) ||
        (point >= 0x2066 && point <= 0x2069))
    ) {
      return true;
    }
  }
  return false;
}

function assertUniqueJsonObjectKeys(source: string): void {
  const end = scanJsonValue(source, skipJsonSpace(source, 0), 0);
  if (skipJsonSpace(source, end) !== source.length) {
    throw new TypeError("Enter a valid JSON array of import rows.");
  }
}

function scanJsonValue(source: string, start: number, depth: number): number {
  if (depth > 32) throw new TypeError("The import JSON is nested too deeply.");
  const index = skipJsonSpace(source, start);
  const token = source[index];
  if (token === '"') return scanJsonString(source, index).next;
  if (token === "[") {
    let cursor = skipJsonSpace(source, index + 1);
    if (source[cursor] === "]") return cursor + 1;
    while (cursor < source.length) {
      cursor = skipJsonSpace(source, scanJsonValue(source, cursor, depth + 1));
      if (source[cursor] === "]") return cursor + 1;
      if (source[cursor] !== ",") break;
      cursor = skipJsonSpace(source, cursor + 1);
    }
  } else if (token === "{") {
    const keys = new Set<string>();
    let cursor = skipJsonSpace(source, index + 1);
    if (source[cursor] === "}") return cursor + 1;
    while (cursor < source.length && source[cursor] === '"') {
      const key = scanJsonString(source, cursor);
      if (keys.has(key.value)) {
        throw new TypeError(
          `The import JSON repeats object property ${JSON.stringify(key.value)}.`,
        );
      }
      keys.add(key.value);
      cursor = skipJsonSpace(source, key.next);
      if (source[cursor] !== ":") break;
      cursor = skipJsonSpace(
        source,
        scanJsonValue(source, cursor + 1, depth + 1),
      );
      if (source[cursor] === "}") return cursor + 1;
      if (source[cursor] !== ",") break;
      cursor = skipJsonSpace(source, cursor + 1);
    }
  } else {
    let cursor = index;
    while (
      cursor < source.length &&
      ![",", "]", "}", " ", "\t", "\r", "\n"].includes(source[cursor]!)
    ) {
      cursor += 1;
    }
    return cursor;
  }
  throw new TypeError("Enter a valid JSON array of import rows.");
}

function scanJsonString(
  source: string,
  start: number,
): { next: number; value: string } {
  let cursor = start + 1;
  while (cursor < source.length) {
    if (source[cursor] === "\\") {
      cursor += 2;
      continue;
    }
    if (source[cursor] === '"') {
      const decoded: unknown = JSON.parse(source.slice(start, cursor + 1));
      if (typeof decoded !== "string") break;
      return { next: cursor + 1, value: decoded };
    }
    cursor += 1;
  }
  throw new TypeError("Enter a valid JSON array of import rows.");
}

function skipJsonSpace(source: string, start: number): number {
  let cursor = start;
  while (
    source[cursor] === " " ||
    source[cursor] === "\t" ||
    source[cursor] === "\r" ||
    source[cursor] === "\n"
  ) {
    cursor += 1;
  }
  return cursor;
}
