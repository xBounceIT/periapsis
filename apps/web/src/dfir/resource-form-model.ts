import type {
  DfirAlertTaskSpec,
  DfirAlertTimelineEventSpec,
  DfirAssetSpec,
  DfirBoundedDocument,
  DfirEntityKind,
  DfirEntityReference,
  DfirIndicatorSpec,
  DfirTaskPriority,
  DfirTaskSpec,
  DfirTimelineEventSpec,
} from "@periapsis/contracts";
import { z } from "zod";
import { isCanonicalUuidV7 } from "../lib/uuid-v7";

const stableKey = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_.-]*$/u, "Use a lowercase stable key.");

const requiredText = (maximum: number) =>
  z.string().trim().min(1, "This field is required.").max(maximum);

const optionalText = (maximum: number) =>
  z.string().trim().max(maximum).optional().or(z.literal(""));

const optionalInstant = optionalText(64).refine(
  (value) => !value || Number.isFinite(Date.parse(value)),
  "Use a valid date and time.",
);

const requiredInstant = requiredText(64).refine(
  (value) => Number.isFinite(Date.parse(value)),
  "Use a valid date and time.",
);

const optionalUuidV7 = optionalText(36).refine(
  (value) => !value || isCanonicalUuidV7(value),
  "Use a canonical UUIDv7.",
);

const uuidV7 = requiredText(36).refine(
  (value) => isCanonicalUuidV7(value),
  "Use a canonical UUIDv7.",
);

const identifierList = optionalText(10_000).superRefine((value, context) => {
  const identifiers = splitList(value);
  if (identifiers.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 UUIDv7 values.",
    });
    return;
  }
  if (identifiers.some((identifier) => !isCanonicalUuidV7(identifier))) {
    context.addIssue({
      code: "custom",
      message: "Every identifier must be a canonical UUIDv7.",
    });
  }
});

const tagList = optionalText(16_640).superRefine((value, context) => {
  const tags = canonicalList(value);
  if (tags.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 unique tags.",
    });
    return;
  }
  if (tags.some((tag) => !/^[a-z][a-z0-9_.:-]{0,63}$/u.test(tag))) {
    context.addIssue({
      code: "custom",
      message: "Use lowercase stable tags of at most 64 characters.",
    });
  }
});

const addressList = optionalText(33_280).superRefine((value, context) => {
  const addresses = splitAddresses(value ?? "");
  if (addresses.ip.length > 256 || addresses.mac.length > 256) {
    context.addIssue({
      code: "custom",
      message: "Use at most 256 IP and 256 MAC addresses.",
    });
    return;
  }
  if (addresses.ip.some((address) => address.length > 45)) {
    context.addIssue({
      code: "custom",
      message: "IP address values must contain at most 45 characters.",
    });
  }
  if (addresses.mac.some((address) => address.length > 64)) {
    context.addIssue({
      code: "custom",
      message: "MAC address values must contain at most 64 characters.",
    });
  }
});

const checklistText = optionalText(51_300).superRefine((value, context) => {
  const titles = splitLines(value);
  if (titles.length > 100) {
    context.addIssue({
      code: "custom",
      message: "Use at most 100 checklist items.",
    });
    return;
  }
  if (titles.some((title) => title.length > 512)) {
    context.addIssue({
      code: "custom",
      message: "Checklist titles must contain at most 512 characters.",
    });
  }
});

const documentText = z
  .string()
  .trim()
  .max(262_144)
  .optional()
  .or(z.literal(""))
  .transform((value, context): DfirBoundedDocument | undefined => {
    if (!value) return undefined;
    try {
      const parsed: unknown = JSON.parse(value);
      if (!isBoundedDocument(parsed)) throw new TypeError("not bounded");
      return parsed;
    } catch {
      context.addIssue({
        code: "custom",
        message: "Use a JSON object within the 64 KiB document limit.",
      });
      return z.NEVER;
    }
  });

export const taskPriorities = [
  "low",
  "medium",
  "high",
  "urgent",
] as const satisfies readonly DfirTaskPriority[];

export const entityKinds = [
  "alert",
  "case",
  "ioc",
  "asset",
  "evidence",
  "task",
  "attachment",
  "external",
] as const satisfies readonly DfirEntityKind[];

export const iocSchema = z
  .object({
    panel: z.literal("iocs"),
    type: z.enum([
      "ipv4",
      "ipv6",
      "domain",
      "hostname",
      "url",
      "email",
      "md5",
      "sha1",
      "sha256",
      "sha512",
      "filename",
      "registry_key",
      "process",
      "mutex",
      "cve",
      "custom",
    ]),
    value: requiredText(8_192),
    description: optionalText(16_384),
    source: requiredText(512),
    confidence: z.coerce.number().int().min(0).max(100),
    tlp: z.enum(["red", "amber", "green", "clear"]),
    firstSeen: optionalInstant,
    lastSeen: optionalInstant,
    malicious: z.enum(["unknown", "benign", "suspicious", "confirmed"]),
    tags: tagList,
    enrichment: documentText,
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.firstSeen,
      value.lastSeen,
      context,
      "lastSeen",
      "Last seen cannot be earlier than first seen.",
    ),
  );

export const assetSchema = z
  .object({
    panel: z.literal("assets"),
    hostname: optionalText(253),
    fqdn: optionalText(253),
    addresses: addressList,
    assetType: stableKey,
    operatingSystem: optionalText(512),
    owner: optionalText(512),
    businessUnit: optionalText(512),
    criticality: z.enum(["low", "medium", "high", "critical"]),
    environment: stableKey,
    externalId: optionalText(512),
    tags: tagList,
    firstSeen: optionalInstant,
    lastSeen: optionalInstant,
    customAttributes: documentText,
  })
  .refine((value) => Boolean(value.hostname || value.fqdn || value.addresses), {
    path: ["hostname"],
    message: "Record a hostname, FQDN, or network address.",
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.firstSeen,
      value.lastSeen,
      context,
      "lastSeen",
      "Last seen cannot be earlier than first seen.",
    ),
  );

export const evidenceSchema = z
  .object({
    panel: z.literal("evidence"),
    title: requiredText(512),
    description: optionalText(16_384),
    evidenceType: stableKey,
    classification: z.enum([
      "public",
      "internal",
      "confidential",
      "restricted",
    ]),
    source: requiredText(512),
    collectedAt: requiredInstant,
    retentionUntil: optionalInstant,
    legalHold: z.boolean().default(false),
    file: fileValue(),
  })
  .superRefine((value, context) =>
    validateInstantOrder(
      value.collectedAt,
      value.retentionUntil,
      context,
      "retentionUntil",
      "Retention cannot end before evidence collection.",
    ),
  );

export const timelineSchema = z.object({
  panel: z.literal("timeline"),
  eventTime: requiredInstant,
  originalTimezone: requiredText(128),
  precision: z.enum([
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "second",
    "millisecond",
    "microsecond",
  ]),
  source: requiredText(512),
  category: stableKey,
  title: requiredText(512),
  description: optionalText(16_384),
  actorId: optionalUuidV7,
  iocIds: identifierList,
  assetIds: identifierList,
  evidenceIds: identifierList,
  tags: tagList,
});

export const taskSchema = z
  .object({
    panel: z.literal("tasks"),
    title: requiredText(512),
    description: optionalText(16_384),
    priority: z.enum(taskPriorities),
    operatorTeamId: optionalUuidV7,
    assigneeId: optionalUuidV7,
    dueAt: optionalInstant,
    checklist: checklistText,
    slaInstanceId: optionalUuidV7,
  })
  .superRefine((value, context) => {
    if (value.assigneeId && !value.operatorTeamId) {
      context.addIssue({
        code: "custom",
        path: ["operatorTeamId"],
        message: "Select an operator team before assigning an operator.",
      });
    }
  });

export const attachmentSchema = z.object({
  panel: z.literal("attachments"),
  visibility: z.enum(["public", "private"]),
  classification: z.enum(["public", "internal", "confidential", "restricted"]),
  file: fileValue(),
});

export const relationshipSchema = z
  .object({
    panel: z.literal("relationships"),
    sourceKind: z.enum(entityKinds),
    sourceId: optionalUuidV7,
    sourceExternalType: optionalText(64),
    sourceExternalId: optionalText(512),
    relationshipType: stableKey,
    targetKind: z.enum(entityKinds),
    targetId: optionalUuidV7,
    targetExternalType: optionalText(64),
    targetExternalId: optionalText(512),
    metadata: documentText,
  })
  .superRefine((value, context) => {
    validateReference(value, "source", context);
    validateReference(value, "target", context);
    if (sameDraftReference(value)) {
      context.addIssue({
        code: "custom",
        path: [
          value.targetKind === "external" ? "targetExternalId" : "targetId",
        ],
        message: "A resource cannot relate to itself.",
      });
    }
  });

export type DfirMutationDraft =
  | z.infer<typeof iocSchema>
  | z.infer<typeof assetSchema>
  | z.infer<typeof evidenceSchema>
  | z.infer<typeof timelineSchema>
  | z.infer<typeof taskSchema>
  | z.infer<typeof attachmentSchema>
  | z.infer<typeof relationshipSchema>;

function fileValue() {
  return z.preprocess(
    (value) => {
      if (typeof FileList !== "undefined" && value instanceof FileList) {
        return value.item(0);
      }
      if (Array.isArray(value)) return value[0];
      return value;
    },
    z.custom<File>(
      (value) => typeof File !== "undefined" && value instanceof File,
      "Select a file.",
    ),
  );
}

type IndicatorDraft = Extract<DfirMutationDraft, { panel: "iocs" }>;

type AssetDraft = Extract<DfirMutationDraft, { panel: "assets" }>;

type TimelineDraft = Extract<DfirMutationDraft, { panel: "timeline" }>;

type TaskDraft = Extract<DfirMutationDraft, { panel: "tasks" }>;

export type DfirSubjectKind = "alert" | "case";

type RelationshipDraft = Extract<DfirMutationDraft, { panel: "relationships" }>;

export function indicatorSpecFromDraft(
  draft: IndicatorDraft,
  fallbackInstant: string,
): DfirIndicatorSpec {
  const firstSeen = formInstant(
    draft.firstSeen || draft.lastSeen || fallbackInstant,
  );
  const lastSeen = formInstant(
    draft.lastSeen || draft.firstSeen || fallbackInstant,
  );
  return {
    confidence: draft.confidence,
    description: draft.description ?? "",
    firstSeen,
    lastSeen,
    malicious: draft.malicious,
    source: draft.source,
    tags: canonicalList(draft.tags),
    tlp: draft.tlp,
    type: draft.type,
    value: draft.value,
    ...(draft.enrichment === undefined ? {} : { enrichment: draft.enrichment }),
  };
}

export function assetSpecFromDraft(
  draft: AssetDraft,
  fallbackInstant: string,
): DfirAssetSpec {
  const addresses = splitAddresses(draft.addresses ?? "");
  const firstSeen = formInstant(
    draft.firstSeen || draft.lastSeen || fallbackInstant,
  );
  const lastSeen = formInstant(
    draft.lastSeen || draft.firstSeen || fallbackInstant,
  );
  return {
    assetType: draft.assetType,
    businessUnit: draft.businessUnit ?? "",
    criticality: draft.criticality,
    environment: draft.environment,
    externalId: draft.externalId ?? "",
    firstSeen,
    fqdn: draft.fqdn ?? "",
    hostname: draft.hostname ?? "",
    ipAddresses: addresses.ip,
    lastSeen,
    macAddresses: addresses.mac,
    operatingSystem: draft.operatingSystem ?? "",
    owner: draft.owner ?? "",
    tags: canonicalList(draft.tags),
    ...(draft.customAttributes === undefined
      ? {}
      : { customAttributes: draft.customAttributes }),
  };
}

export function timelineSpecFromDraft(
  draft: TimelineDraft,
  _subjectKind: DfirSubjectKind,
): DfirTimelineEventSpec | DfirAlertTimelineEventSpec {
  return {
    ...(draft.actorId ? { actorId: draft.actorId } : {}),
    assetIds: canonicalList(draft.assetIds),
    category: draft.category,
    description: draft.description ?? "",
    eventTime: formInstant(draft.eventTime),
    evidenceIds: canonicalList(draft.evidenceIds),
    iocIds: canonicalList(draft.iocIds),
    originalTimezone: draft.originalTimezone,
    precision: draft.precision,
    source: draft.source,
    tags: canonicalList(draft.tags),
    title: draft.title,
  };
}

export function taskSpecFromDraft(
  draft: TaskDraft,
  checklistItemIds: readonly string[],
): DfirTaskSpec {
  const checklist = splitLines(draft.checklist);
  if (checklist.length > checklistItemIds.length) {
    throw new TypeError(
      "Checklist identifiers are unavailable for this intent.",
    );
  }
  return {
    ...(draft.assigneeId ? { assigneeId: draft.assigneeId } : {}),
    checklist: checklist.map((title, index) => ({
      completed: false,
      id: checklistItemIds[index]!,
      title,
    })),
    description: draft.description ?? "",
    ...(draft.dueAt ? { dueAt: formInstant(draft.dueAt) } : {}),
    ...(draft.operatorTeamId ? { operatorTeamId: draft.operatorTeamId } : {}),
    priority: draft.priority,
    ...(draft.slaInstanceId ? { slaInstanceId: draft.slaInstanceId } : {}),
    title: draft.title,
  };
}

export function alertTaskSpecFromDraft(
  draft: TaskDraft,
  checklistItemIds: readonly string[],
): DfirAlertTaskSpec {
  const task = taskSpecFromDraft(draft, checklistItemIds);
  return {
    ...(task.assigneeId ? { assigneeId: task.assigneeId } : {}),
    checklist: task.checklist.map(({ completed, id, title }) => ({
      completed,
      id,
      title,
    })),
    description: task.description,
    ...(task.dueAt ? { dueAt: task.dueAt } : {}),
    ...(task.operatorTeamId ? { operatorTeamId: task.operatorTeamId } : {}),
    priority: task.priority,
    ...(task.slaInstanceId ? { slaInstanceId: task.slaInstanceId } : {}),
    title: task.title,
  };
}

export function relationshipReferenceFromDraft(
  draft: RelationshipDraft,
  side: "source" | "target",
): DfirEntityReference {
  const kind = draft[`${side}Kind`];
  if (kind === "external") {
    return {
      externalId: draft[`${side}ExternalId`] ?? "",
      externalType: draft[`${side}ExternalType`] ?? "",
      kind,
    };
  }
  return { id: draft[`${side}Id`] ?? "", kind };
}

function canonicalList(value: string | undefined): string[] {
  return [...new Set(splitList(value))].toSorted(codePointCompare);
}

export function formInstant(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) {
    throw new TypeError("A valid investigation timestamp is required.");
  }
  const normalized = instant.toISOString();
  const fraction = instantFraction(value);
  return fraction ? `${normalized.slice(0, 19)}.${fraction}Z` : normalized;
}

export function instantInputValue(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) return "";
  const local = new Date(
    instant.valueOf() - instant.getTimezoneOffset() * 60_000,
  );
  const base = local.toISOString().slice(0, 19);
  const fraction = instantFraction(value);
  return fraction ? `${base}.${fraction}` : base;
}

export function documentInputValue(
  value: DfirBoundedDocument | undefined,
): string {
  return value === undefined ? "" : JSON.stringify(value, undefined, 2);
}

export function parseOptionalDocumentText(
  value: string,
): DfirBoundedDocument | undefined {
  const result = documentText.safeParse(value);
  if (!result.success) {
    throw new TypeError(
      result.error.issues[0]?.message ?? "Use a valid JSON object.",
    );
  }
  return result.data;
}

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function instantFraction(value: string): string | undefined {
  return /\.(?<fraction>\d+)(?:Z|[+-]\d{2}:\d{2})?$/u.exec(value)?.groups?.[
    "fraction"
  ];
}

function splitLines(value: string | undefined): string[] {
  return (value ?? "")
    .split(/\r?\n/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitAddresses(value: string): { ip: string[]; mac: string[] } {
  const ip: string[] = [];
  const mac: string[] = [];
  for (const address of canonicalList(value)) {
    if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/iu.test(address))
      mac.push(address);
    else ip.push(address);
  }
  return { ip, mac };
}

function codePointCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isBoundedDocument(value: unknown): value is DfirBoundedDocument {
  if (!isRecord(value)) return false;
  const count = { values: 0 };
  if (!visitDocumentValue(value, 1, count)) return false;
  return new TextEncoder().encode(JSON.stringify(value)).byteLength <= 65_536;
}

function visitDocumentValue(
  value: unknown,
  depth: number,
  count: { values: number },
): boolean {
  count.values += 1;
  if (depth > 32 || count.values > 4_096) return false;
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    return (
      value.length <= 4_096 &&
      value.every((item) => visitDocumentValue(item, depth + 1, count))
    );
  }
  if (!isRecord(value) || Object.keys(value).length > 200) return false;
  return Object.entries(value).every(
    ([key, item]) =>
      key.length >= 1 &&
      key.length <= 512 &&
      !hasControlCharacter(key) &&
      visitDocumentValue(item, depth + 1, count),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || codeUnit === 0x7f) return true;
  }
  return false;
}

function validateInstantOrder(
  first: string | undefined,
  last: string | undefined,
  context: z.RefinementCtx,
  path: string,
  message: string,
): void {
  if (first && last && Date.parse(last) < Date.parse(first)) {
    context.addIssue({
      code: "custom",
      path: [path],
      message,
    });
  }
}

function validateReference(
  value: z.infer<typeof relationshipSchema>,
  side: "source" | "target",
  context: z.RefinementCtx,
): void {
  const kind = value[`${side}Kind`];
  if (kind === "external") {
    if (!stableKey.safeParse(value[`${side}ExternalType`]).success) {
      context.addIssue({
        code: "custom",
        path: [`${side}ExternalType`],
        message: "Use a lowercase stable external type.",
      });
    }
    if (!value[`${side}ExternalId`]) {
      context.addIssue({
        code: "custom",
        path: [`${side}ExternalId`],
        message: "An external identifier is required.",
      });
    }
    return;
  }
  if (!uuidV7.safeParse(value[`${side}Id`]).success) {
    context.addIssue({
      code: "custom",
      path: [`${side}Id`],
      message: "A canonical UUIDv7 is required.",
    });
  }
}

function sameDraftReference(
  value: z.infer<typeof relationshipSchema>,
): boolean {
  if (value.sourceKind !== value.targetKind) return false;
  return value.sourceKind === "external"
    ? value.sourceExternalType === value.targetExternalType &&
        value.sourceExternalId === value.targetExternalId &&
        Boolean(value.sourceExternalType && value.sourceExternalId)
    : value.sourceId === value.targetId && Boolean(value.sourceId);
}
