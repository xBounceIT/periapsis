import type {
  DfirAssetCriticality,
  DfirEvidenceClassification,
  DfirIndicatorType,
  DfirMaliciousState,
  DfirScanState,
  DfirTaskPriority,
  DfirTaskStatus,
  DfirTemporalPrecision,
  DfirTlp,
  DfirVisibility,
} from "@periapsis/contracts";

import { formatTenantInstant } from "../lib/tenant-date-time-context";

export type DfirPanel =
  | "iocs"
  | "assets"
  | "evidence"
  | "timeline"
  | "tasks"
  | "attachments"
  | "relationships";

export type DfirAlertPanel = DfirPanel;

export type DfirPermission =
  | "dfir.ioc.manage"
  | "dfir.asset.manage"
  | "dfir.evidence.manage"
  | "dfir.timeline.manage"
  | "dfir.task.manage"
  | "dfir.attachment.manage"
  | "dfir.relationship.manage";

export type DfirReadPermission =
  | "dfir.ioc.read"
  | "dfir.asset.read"
  | "dfir.evidence.read"
  | "dfir.timeline.read"
  | "dfir.task.read"
  | "dfir.attachment.read"
  | "dfir.relationship.read";

export const dfirReadPermissions = [
  "dfir.ioc.read",
  "dfir.asset.read",
  "dfir.evidence.read",
  "dfir.timeline.read",
  "dfir.task.read",
  "dfir.attachment.read",
  "dfir.relationship.read",
] as const satisfies readonly DfirReadPermission[];

export const alertDfirReadPermissions = [
  "dfir.ioc.read",
  "dfir.asset.read",
  "dfir.evidence.read",
  "dfir.timeline.read",
  "dfir.task.read",
  "dfir.attachment.read",
  "dfir.relationship.read",
] as const satisfies readonly DfirReadPermission[];

export interface IOCView {
  relatedRoots: readonly { kind: "case" | "alert"; id: string }[];
  id: string;
  type: DfirIndicatorType;
  value: string;
  confidence: number;
  tlp: DfirTlp;
  malicious: DfirMaliciousState;
  tags: readonly string[];
}

export interface AssetView {
  relatedRoots: readonly { kind: "case" | "alert"; id: string }[];
  id: string;
  hostname?: string;
  fqdn?: string;
  addresses: readonly string[];
  assetType: string;
  criticality: DfirAssetCriticality;
  environment: string;
}

export interface CustodyEventView {
  id: string;
  sequence: number;
  action: string;
  occurredAt: string;
  actorLabel: string;
}

export interface EvidenceView {
  id: string;
  title: string;
  evidenceType: string;
  classification: DfirEvidenceClassification;
  scanState: DfirScanState;
  sizeBytes: number;
  sha256: string;
  legalHold: boolean;
  custody: readonly CustodyEventView[];
}

export interface TimelineEventView {
  id: string;
  eventTime: string;
  precision: DfirTemporalPrecision;
  category: string;
  title: string;
  description?: string;
  source: string;
}

export interface TaskView {
  id: string;
  title: string;
  status: DfirTaskStatus;
  priority: DfirTaskPriority;
  dueAt?: string;
  assigneeLabel?: string;
  checklistCompleted: number;
  checklistTotal: number;
  version: number;
}

export interface AttachmentView {
  id: string;
  filename: string;
  visibility: DfirVisibility;
  scanState: DfirScanState;
  uploadedAt: string;
  sizeBytes?: number;
}

export interface RelationshipView {
  id: string;
  sourceLabel: string;
  relationshipType: string;
  targetLabel: string;
}

export interface DfirCaseData {
  iocs: readonly IOCView[];
  assets: readonly AssetView[];
  evidence: readonly EvidenceView[];
  timeline: readonly TimelineEventView[];
  tasks: readonly TaskView[];
  attachments: readonly AttachmentView[];
  relationships: readonly RelationshipView[];
}

export type DfirAlertData = DfirCaseData;

export interface DfirProblem {
  status: number;
}

export function safeDfirProblem(problem: DfirProblem): string {
  switch (problem.status) {
    case 400:
      return "Review the investigation fields and their Case binding before retrying.";
    case 401:
      return "Your session is no longer valid. Sign in again before reopening this investigation.";
    case 403:
      return "Your current assignment no longer permits this investigation action.";
    case 404:
      return "This investigation record is unavailable in the active tenant.";
    case 409:
      return "The investigation changed while you were working. Reload the latest case state.";
    case 412:
    case 428:
      return "This case view is stale. Reload before retrying the action.";
    case 422:
      return "The investigation input or uploaded object could not be accepted.";
    case 503:
      return "The investigation service is temporarily unavailable.";
    default:
      return "The investigation data is temporarily unavailable.";
  }
}

export function safeAlertDfirProblem(problem: DfirProblem): string {
  switch (problem.status) {
    case 400:
      return "Review the investigation fields and their Alert binding before retrying.";
    case 401:
      return "Your session is no longer valid. Sign in again before reopening this investigation.";
    case 403:
      return "Your current assignment no longer permits this Alert investigation action.";
    case 404:
      return "This Alert investigation record is unavailable in the active tenant.";
    case 409:
      return "The investigation changed while you were working. Reload the latest Alert state.";
    case 412:
    case 428:
      return "This Alert investigation view is stale. Reload before retrying the action.";
    case 422:
      return "The investigation input or uploaded object could not be accepted.";
    case 503:
      return "The Alert investigation service is temporarily unavailable.";
    default:
      return "The Alert investigation data is temporarily unavailable.";
  }
}

export function formatForensicInstant(value: string): string {
  return formatTenantInstant(value);
}

export function formatEvidenceBytes(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) return "Invalid size";
  if (value < 1_024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"] as const;
  let amount = value / 1_024;
  let unit: (typeof units)[number] = units[0];
  for (let index = 1; index < units.length && amount >= 1_024; index += 1) {
    amount /= 1_024;
    unit = units[index]!;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(amount)} ${unit}`;
}

export function compactDigest(value: string): string {
  return /^[0-9a-f]{64}$/u.test(value)
    ? `${value.slice(0, 12)}…${value.slice(-12)}`
    : "Invalid digest";
}
