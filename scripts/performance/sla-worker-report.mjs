const digestPattern = /^[0-9a-f]{64}$/u;
const counters = [
  "batches",
  "claimed",
  "completed",
  "replayed",
  "retryScheduled",
  "deadLettered",
  "fenceLost",
  "durationMs",
  "processingMs",
];
const queueFields = [
  "total",
  "queued",
  "leased",
  "retryScheduled",
  "completed",
  "deadLettered",
];

function count(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function queue(value) {
  if (!value || queueFields.some((key) => !count(value[key]))) {
    throw new Error("SLA worker queue report is malformed");
  }
  const result = Object.fromEntries(
    queueFields.map((key) => [key, value[key]]),
  );
  if (
    queueFields.slice(1).reduce((total, key) => total + result[key], 0) !==
    result.total
  ) {
    throw new Error("SLA worker queue totals disagree");
  }
  return result;
}

// Retain only bounded protocol fields, never arbitrary child output.
export function parseSlaWorkerReport(output, mode) {
  let raw;
  try {
    raw = JSON.parse(output);
  } catch {
    throw new Error("SLA worker report is not JSON");
  }
  if (
    !["ingress", "timers"].includes(mode) ||
    !raw ||
    raw.schemaVersion !== 1 ||
    raw.mode !== mode ||
    !["passed", "failed"].includes(raw.status) ||
    counters.some((key) => !count(raw[key]))
  ) {
    throw new Error("SLA worker report is malformed");
  }
  const result = {
    schemaVersion: 1,
    mode,
    status: raw.status,
    ...Object.fromEntries(counters.map((key) => [key, raw[key]])),
  };
  if (raw.errorCode !== undefined) {
    if (
      typeof raw.errorCode !== "string" ||
      !/^[a-z_]{1,40}$/u.test(raw.errorCode)
    ) {
      throw new Error("SLA worker error code is malformed");
    }
    result.errorCode = raw.errorCode;
  }
  for (const key of ["queueBefore", "queueAfter"]) {
    if (raw[key] !== undefined) result[key] = queue(raw[key]);
  }
  for (const key of ["snapshotBefore", "snapshotAfter", "receiptsDigest"]) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "string" || !digestPattern.test(raw[key]))
        throw new Error("SLA worker digest is malformed");
      result[key] = raw[key];
    }
  }
  result.snapshotsStable = raw.snapshotsStable === true;
  if (raw.outcomes !== undefined) {
    if (
      typeof raw.outcomes !== "object" ||
      raw.outcomes === null ||
      Array.isArray(raw.outcomes)
    ) {
      throw new Error("SLA worker outcomes are malformed");
    }
    const entries = Object.entries(raw.outcomes);
    if (
      entries.length > 32 ||
      entries.some(
        ([key, value]) =>
          !/^[a-z_]{1,32}(?:\/[a-z_]{1,32}){0,2}$/u.test(key) || !count(value),
      )
    ) {
      throw new Error("SLA worker outcomes are malformed");
    }
    result.outcomes = Object.fromEntries(entries);
  }
  return result;
}

export function assertSlaWorkerReport(report, mode) {
  if (
    !["ingress", "timers"].includes(mode) ||
    report.status !== "passed" ||
    report.mode !== mode ||
    report.errorCode ||
    report.claimed !== report.completed + report.replayed ||
    report.retryScheduled !== 0 ||
    report.deadLettered !== 0 ||
    report.fenceLost !== 0 ||
    !report.queueBefore ||
    !report.queueAfter ||
    (report.claimed > 0 && !digestPattern.test(report.receiptsDigest))
  ) {
    throw new Error("SLA worker did not prove successful processing");
  }
  if (
    mode === "ingress" &&
    (!report.snapshotsStable ||
      !digestPattern.test(report.snapshotBefore) ||
      report.snapshotBefore !== report.snapshotAfter ||
      report.queueAfter.total !== report.queueAfter.completed ||
      report.queueBefore.total !== report.queueAfter.total ||
      report.queueAfter.completed - report.queueBefore.completed !==
        report.claimed)
  ) {
    throw new Error(
      "SLA ingress settlement or immutable snapshot proof failed",
    );
  }
  if (
    mode === "timers" &&
    (report.batches !== 1 ||
      report.claimed !== 100 ||
      report.completed !== 100 ||
      report.replayed !== 0)
  ) {
    throw new Error("SLA timer worker did not finalize exactly one batch");
  }
}
