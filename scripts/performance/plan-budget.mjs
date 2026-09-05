import { Buffer } from "node:buffer";

const finiteNonNegative = (value) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;
const postgresIdentifier = (value) =>
  typeof value === "string" && /^[a-z][a-z0-9_]{0,62}$/.test(value);

function requireRecord(value, message) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(message);
  }
  return value;
}

export function parseExplainJson(source) {
  if (
    typeof source !== "string" ||
    source.trim() === "" ||
    Buffer.byteLength(source, "utf8") > 2 * 1024 * 1024
  ) {
    throw new TypeError("EXPLAIN evidence is empty");
  }
  let decoded;
  try {
    decoded = JSON.parse(source.trim().replace(/^\uFEFF/, ""));
  } catch (error) {
    throw new TypeError("EXPLAIN evidence is not valid JSON", { cause: error });
  }
  if (!Array.isArray(decoded) || decoded.length !== 1) {
    throw new TypeError("EXPLAIN evidence must contain exactly one statement");
  }
  const statement = requireRecord(decoded[0], "EXPLAIN statement is malformed");
  requireRecord(statement.Plan, "EXPLAIN root plan is missing");
  if (
    !finiteNonNegative(statement["Planning Time"]) ||
    !finiteNonNegative(statement["Execution Time"])
  ) {
    throw new TypeError("EXPLAIN timing evidence is missing");
  }
  return decoded;
}

function planNodes(root) {
  const nodes = [];
  const pending = [root];
  while (pending.length > 0) {
    if (nodes.length >= 10_000) {
      throw new TypeError("EXPLAIN plan exceeds the bounded node count");
    }
    const node = requireRecord(pending.pop(), "EXPLAIN node is malformed");
    if (typeof node["Node Type"] !== "string" || node["Node Type"] === "") {
      throw new TypeError("EXPLAIN node type is missing");
    }
    nodes.push(node);
    if (node.Plans !== undefined) {
      if (!Array.isArray(node.Plans)) {
        throw new TypeError("EXPLAIN child plans are malformed");
      }
      for (let index = node.Plans.length - 1; index >= 0; index -= 1) {
        pending.push(node.Plans[index]);
      }
    }
  }
  return nodes;
}

function rootCounter(root, name) {
  const value = root[name];
  if (!finiteNonNegative(value)) {
    throw new TypeError(`EXPLAIN ${name} is malformed`);
  }
  return value;
}

export function summarizePlan(explain) {
  if (!Array.isArray(explain) || explain.length !== 1) {
    throw new TypeError("EXPLAIN document is malformed");
  }
  const statement = requireRecord(explain[0], "EXPLAIN statement is malformed");
  const root = requireRecord(statement.Plan, "EXPLAIN root plan is missing");
  const nodes = planNodes(root);
  const indexes = new Set();
  const sequentialScans = new Set();
  const diskSorts = [];
  const scanEvidence = [];
  for (const node of nodes) {
    const actualRows = node["Actual Rows"];
    const actualLoops = node["Actual Loops"];
    if (!finiteNonNegative(actualRows) || !finiteNonNegative(actualLoops)) {
      throw new TypeError("EXPLAIN node execution counters are malformed");
    }
    const executed = actualLoops > 0;
    const contributedRows = executed && actualRows * actualLoops > 0;
    if (contributedRows && typeof node["Index Name"] === "string") {
      indexes.add(node["Index Name"]);
    }
    if (
      executed &&
      new Set(["Seq Scan", "Parallel Seq Scan"]).has(node["Node Type"]) &&
      typeof node["Relation Name"] === "string"
    ) {
      sequentialScans.add(node["Relation Name"]);
    }
    if (
      typeof node["Relation Name"] === "string" ||
      typeof node["Index Name"] === "string"
    ) {
      scanEvidence.push(
        Object.freeze({
          nodeType: node["Node Type"],
          relation: node["Relation Name"] ?? null,
          index: node["Index Name"] ?? null,
          actualRows,
          actualLoops,
          totalRows: actualRows * actualLoops,
        }),
      );
    }
    if (executed && node["Sort Space Type"] === "Disk") {
      diskSorts.push(
        Object.freeze({
          method: String(node["Sort Method"] ?? "unknown"),
          spaceKilobytes: Number(node["Sort Space Used"] ?? 0),
        }),
      );
    }
  }
  const actualRows = root["Actual Rows"];
  const actualLoops = root["Actual Loops"];
  if (!finiteNonNegative(actualRows) || !finiteNonNegative(actualLoops)) {
    throw new TypeError("EXPLAIN actual row count is missing");
  }
  const sharedHitBlocks = rootCounter(root, "Shared Hit Blocks");
  const sharedReadBlocks = rootCounter(root, "Shared Read Blocks");
  const tempReadBlocks = rootCounter(root, "Temp Read Blocks");
  const tempWrittenBlocks = rootCounter(root, "Temp Written Blocks");
  return Object.freeze({
    executionMs: statement["Execution Time"],
    planningMs: statement["Planning Time"],
    actualRows,
    actualLoops,
    nodeCount: nodes.length,
    indexes: Object.freeze([...indexes].toSorted()),
    sequentialScans: Object.freeze([...sequentialScans].toSorted()),
    diskSorts: Object.freeze(diskSorts),
    scans: Object.freeze(scanEvidence),
    buffers: Object.freeze({
      sharedHitBlocks,
      sharedReadBlocks,
      tempReadBlocks,
      tempWrittenBlocks,
    }),
    sharedBlocks: sharedHitBlocks + sharedReadBlocks,
    tempBlocks: tempReadBlocks + tempWrittenBlocks,
  });
}

function requireBudgetNumber(budget, key) {
  if (!finiteNonNegative(budget[key])) {
    throw new TypeError(`plan budget ${key} is invalid`);
  }
  return budget[key];
}

function assertIndexAlternatives(summary, alternatives, failures) {
  const malformedBudget = "plan index alternative budget is malformed";
  requireRecord(alternatives, malformedBudget);
  if (
    Object.keys(alternatives).length !== 2 ||
    !Object.hasOwn(alternatives, "relation") ||
    !Object.hasOwn(alternatives, "indexes") ||
    !postgresIdentifier(alternatives.relation) ||
    !Array.isArray(alternatives.indexes) ||
    alternatives.indexes.length === 0 ||
    !Array.from(alternatives.indexes).every(postgresIdentifier) ||
    new Set(alternatives.indexes).size !== alternatives.indexes.length
  ) {
    throw new TypeError(malformedBudget);
  }
  const malformedScans = "plan index alternative scan evidence is malformed";
  if (!Array.isArray(summary.scans)) {
    throw new TypeError(malformedScans);
  }
  for (const scan of summary.scans) {
    requireRecord(scan, malformedScans);
  }
  // Require relation and index on the same contributing scan. A global index
  // name, a dead branch, or a bitmap index without relation provenance is not
  // evidence of this access path.
  const used = summary.scans.some(
    (scan) =>
      (scan.nodeType === "Index Scan" || scan.nodeType === "Index Only Scan") &&
      scan.relation === alternatives.relation &&
      alternatives.indexes.includes(scan.index) &&
      finiteNonNegative(scan.actualRows) &&
      finiteNonNegative(scan.actualLoops) &&
      finiteNonNegative(scan.totalRows) &&
      scan.actualRows > 0 &&
      scan.actualLoops > 0 &&
      scan.totalRows > 0 &&
      scan.totalRows === scan.actualRows * scan.actualLoops,
  );
  if (!used) {
    failures.push(
      `required index alternative for ${alternatives.relation} was not used`,
    );
  }
}

export function assertPlanBudget(name, summary, budget) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9_]{2,63}$/.test(name)) {
    throw new TypeError("plan gate name is invalid");
  }
  requireRecord(summary, "plan summary is malformed");
  requireRecord(budget, "plan budget is malformed");
  const failures = [];
  if (summary.actualLoops !== 1) {
    failures.push(`root loops ${summary.actualLoops} differs from 1`);
  }
  for (const [metric, actual, budgetKey] of [
    ["execution time", summary.executionMs, "maxExecutionMs"],
    ["planning time", summary.planningMs, "maxPlanningMs"],
    ["shared blocks", summary.sharedBlocks, "maxSharedBlocks"],
    ["temporary blocks", summary.tempBlocks, "maxTempBlocks"],
    ["result rows", summary.actualRows, "maxResultRows"],
  ]) {
    const maximum = requireBudgetNumber(budget, budgetKey);
    if (!finiteNonNegative(actual) || actual > maximum) {
      failures.push(`${metric} ${actual} exceeds ${maximum}`);
    }
  }
  const minimumResultRows = requireBudgetNumber(budget, "minResultRows");
  const maximumResultRows = requireBudgetNumber(budget, "maxResultRows");
  if (
    !Number.isSafeInteger(minimumResultRows) ||
    !Number.isSafeInteger(maximumResultRows) ||
    minimumResultRows > maximumResultRows
  ) {
    throw new TypeError("plan result-row bounds are invalid");
  }
  if (summary.actualRows < minimumResultRows) {
    failures.push(
      `result rows ${summary.actualRows} is below ${minimumResultRows}`,
    );
  }
  const requiredIndexes = budget.requiredIndexes ?? [];
  const forbiddenSequentialScans = budget.forbiddenSequentialScans ?? [];
  if (
    !Array.isArray(requiredIndexes) ||
    !requiredIndexes.every(
      (value) => typeof value === "string" && value !== "",
    ) ||
    !Array.isArray(forbiddenSequentialScans) ||
    !forbiddenSequentialScans.every(
      (value) => typeof value === "string" && value !== "",
    )
  ) {
    throw new TypeError("plan index or scan budget is malformed");
  }
  for (const index of requiredIndexes) {
    if (!summary.indexes.includes(index)) {
      failures.push(`required index ${index} was not used`);
    }
  }
  if (Object.hasOwn(budget, "requiredIndexAlternatives")) {
    assertIndexAlternatives(
      summary,
      budget.requiredIndexAlternatives,
      failures,
    );
  }
  for (const relation of forbiddenSequentialScans) {
    if (summary.sequentialScans.includes(relation)) {
      failures.push(`sequential scan used on ${relation}`);
    }
  }
  if (!Array.isArray(summary.diskSorts) || summary.diskSorts.length > 0) {
    failures.push("query spilled a sort to disk");
  }
  if (failures.length > 0) {
    throw new Error(`${name} plan budget failed: ${failures.join("; ")}`);
  }
}

export function assertLoadBudget(name, summary, budget) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9_]{2,63}$/.test(name)) {
    throw new TypeError("load gate name is invalid");
  }
  requireRecord(summary, "load summary is malformed");
  requireRecord(budget, "load budget is malformed");
  const operations = summary.operations;
  const successfulOperations = summary.successfulOperations;
  const distinctOperations = summary.distinctOperations;
  const wallMs = summary.wallMs;
  const maximumWorkerMs = summary.maximumWorkerMs;
  if (
    !Number.isSafeInteger(operations) ||
    operations <= 0 ||
    !Number.isSafeInteger(successfulOperations) ||
    successfulOperations < 0 ||
    successfulOperations > operations ||
    !Number.isSafeInteger(distinctOperations) ||
    distinctOperations < 0 ||
    distinctOperations > successfulOperations ||
    !finiteNonNegative(wallMs) ||
    wallMs === 0 ||
    !finiteNonNegative(maximumWorkerMs) ||
    maximumWorkerMs === 0
  ) {
    throw new TypeError("load summary counters are malformed");
  }
  const expectedOperations = requireBudgetNumber(budget, "expectedOperations");
  const maxWallMs = requireBudgetNumber(budget, "maxWallMs");
  const maxWorkerMs = requireBudgetNumber(budget, "maxWorkerMs");
  const minOperationsPerSecond = requireBudgetNumber(
    budget,
    "minOperationsPerSecond",
  );
  if (
    !Number.isSafeInteger(expectedOperations) ||
    expectedOperations <= 0 ||
    maxWallMs <= 0 ||
    maxWorkerMs <= 0 ||
    minOperationsPerSecond <= 0
  ) {
    throw new TypeError("load budget bounds are invalid");
  }
  const operationsPerSecond = (distinctOperations * 1000) / wallMs;
  const failures = [];
  if (operations !== expectedOperations) {
    failures.push(
      `operations ${operations} differs from ${expectedOperations}`,
    );
  }
  if (successfulOperations !== operations) {
    failures.push(
      `successful operations ${successfulOperations} differs from ${operations}`,
    );
  }
  if (distinctOperations !== successfulOperations) {
    failures.push(
      `distinct operations ${distinctOperations} differs from successful operations ${successfulOperations}`,
    );
  }
  if (wallMs > maxWallMs) {
    failures.push(`wall time ${wallMs} exceeds ${maxWallMs}`);
  }
  if (maximumWorkerMs > maxWorkerMs) {
    failures.push(`worker time ${maximumWorkerMs} exceeds ${maxWorkerMs}`);
  }
  if (operationsPerSecond < minOperationsPerSecond) {
    failures.push(
      `throughput ${operationsPerSecond.toFixed(2)} is below ${minOperationsPerSecond}`,
    );
  }
  if (failures.length > 0) {
    throw new Error(`${name} load budget failed: ${failures.join("; ")}`);
  }
  return operationsPerSecond;
}
