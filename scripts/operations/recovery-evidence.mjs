import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { open, unlink } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

const MAX_INPUT_BYTES = 1024 * 1024;
const MAX_KEY_BYTES = 64 * 1024;
const MAX_EVIDENCE_BYTES = 64 * 1024 * 1024;
const REQUIRED_EVIDENCE_LABELS = new Set([
  "audit-chain",
  "cross-tenant",
  "object-inventory",
  "readiness",
  "rls-roles",
  "schema-compatibility",
]);

export async function buildRecoveryManifest(input) {
  assertRecord(input, "input");
  assertExactKeys(
    input,
    [
      "acceptance",
      "audit",
      "database",
      "drillId",
      "environment",
      "evidenceFiles",
      "release",
      "storage",
      "window",
    ],
    "input",
  );
  assertUuid(input.drillId, "input.drillId");
  assertBoundedString(
    input.environment,
    "input.environment",
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u,
  );

  const release = validateRelease(input.release);
  const window = validateWindow(input.window);
  const database = validateDatabase(input.database);
  const audit = validateAudit(input.audit);
  const storage = validateStorage(input.storage);
  const acceptance = validateAcceptance(input.acceptance);
  const evidence = await hashEvidenceFiles(input.evidenceFiles);

  return {
    schemaVersion: 1,
    drillId: input.drillId,
    environment: input.environment,
    release,
    window,
    database,
    audit,
    storage,
    acceptance,
    evidence,
  };
}

export function sealRecoveryManifest(manifest, privateKeyPem) {
  validateManifest(manifest);
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("the recovery evidence signing key must be Ed25519");
  }
  const publicKey = createPublicKey(privateKey);
  const manifestBytes = Buffer.from(canonicalJson(manifest), "utf8");
  const signature = sign(null, manifestBytes, privateKey);
  const publicDer = publicKey.export({ type: "spki", format: "der" });

  return {
    manifestBytes,
    envelope: {
      schemaVersion: 1,
      algorithm: "Ed25519",
      keyId: `sha256:${sha256(publicDer)}`,
      manifestSha256: sha256(manifestBytes),
      signature: signature.toString("base64url"),
    },
  };
}

export function verifyRecoveryEnvelope(manifestBytes, envelope, publicKeyPem) {
  if (
    !Buffer.isBuffer(manifestBytes) ||
    manifestBytes.length > MAX_INPUT_BYTES
  ) {
    throw new Error("manifest bytes are required");
  }
  assertRecord(envelope, "signature envelope");
  assertExactKeys(
    envelope,
    ["algorithm", "keyId", "manifestSha256", "schemaVersion", "signature"],
    "signature envelope",
  );
  if (envelope.schemaVersion !== 1 || envelope.algorithm !== "Ed25519") {
    throw new Error("unsupported recovery evidence signature envelope");
  }
  assertDigest(envelope.manifestSha256, "signature envelope manifestSha256");
  assertBoundedString(
    envelope.keyId,
    "signature envelope keyId",
    /^sha256:[0-9a-f]{64}$/u,
  );
  assertBoundedString(
    envelope.signature,
    "signature envelope signature",
    /^[A-Za-z0-9_-]{86}$/u,
  );

  const manifestText = manifestBytes.toString("utf8");
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    throw new Error("recovery evidence manifest is not valid JSON");
  }
  validateManifest(manifest);
  if (canonicalJson(manifest) !== manifestText) {
    throw new Error("recovery evidence manifest is not canonical JSON");
  }
  if (sha256(manifestBytes) !== envelope.manifestSha256) {
    throw new Error("recovery evidence manifest digest mismatch");
  }

  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("the recovery evidence verification key must be Ed25519");
  }
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  if (`sha256:${sha256(publicDer)}` !== envelope.keyId) {
    throw new Error("recovery evidence verification key does not match keyId");
  }
  const signature = Buffer.from(envelope.signature, "base64url");
  if (
    signature.length !== 64 ||
    signature.toString("base64url") !== envelope.signature ||
    !verify(null, manifestBytes, publicKey, signature)
  ) {
    throw new Error("recovery evidence signature is invalid");
  }
  return manifest;
}

export function canonicalJson(value) {
  return `${JSON.stringify(sortJson(value))}\n`;
}

export async function main(argv = process.argv.slice(2)) {
  const [action, ...argumentsList] = argv;
  const options = parseOptions(argumentsList);
  if (action === "seal") {
    requireOptions(options, ["input", "manifest", "private-key", "signature"]);
    if (options.manifest === options.signature) {
      throw new Error("manifest and signature outputs must be different files");
    }
    const input = await readJson(options.input, MAX_INPUT_BYTES, "drill input");
    const privateKey = await readBoundedFile(
      options["private-key"],
      MAX_KEY_BYTES,
      "private key",
    );
    const manifest = await buildRecoveryManifest(input);
    const sealed = sealRecoveryManifest(manifest, privateKey);
    await writePairExclusive(
      options.manifest,
      sealed.manifestBytes,
      options.signature,
      Buffer.from(canonicalJson(sealed.envelope), "utf8"),
    );
    return;
  }
  if (action === "verify") {
    requireOptions(options, ["manifest", "public-key", "signature"]);
    const manifestBytes = await readBoundedFile(
      options.manifest,
      MAX_INPUT_BYTES,
      "manifest",
    );
    const envelope = await readJson(
      options.signature,
      MAX_INPUT_BYTES,
      "signature envelope",
    );
    const publicKey = await readBoundedFile(
      options["public-key"],
      MAX_KEY_BYTES,
      "public key",
    );
    verifyRecoveryEnvelope(manifestBytes, envelope, publicKey);
    return;
  }
  throw new Error(
    "usage: recovery-evidence.mjs seal|verify --manifest <file> --signature <file> ...",
  );
}

function validateRelease(value) {
  assertRecord(value, "input.release");
  assertExactKeys(
    value,
    [
      "latestMigrationSha256",
      "releaseManifestSha256",
      "schemaJournalCount",
      "version",
    ],
    "input.release",
  );
  assertBoundedString(
    value.version,
    "input.release.version",
    /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/u,
  );
  assertDigest(
    value.releaseManifestSha256,
    "input.release.releaseManifestSha256",
  );
  assertDigest(
    value.latestMigrationSha256,
    "input.release.latestMigrationSha256",
  );
  assertInteger(
    value.schemaJournalCount,
    "input.release.schemaJournalCount",
    1,
    1_000_000,
  );
  return { ...value };
}

function validateWindow(value) {
  assertRecord(value, "input.window");
  assertExactKeys(
    value,
    [
      "completedAt",
      "incidentCutoffAt",
      "maxRpoSeconds",
      "maxRtoSeconds",
      "recoveryPointAt",
      "startedAt",
    ],
    "input.window",
  );
  const startedAt = parseInstant(value.startedAt, "input.window.startedAt");
  const completedAt = parseInstant(
    value.completedAt,
    "input.window.completedAt",
  );
  const incidentCutoffAt = parseInstant(
    value.incidentCutoffAt,
    "input.window.incidentCutoffAt",
  );
  const recoveryPointAt = parseInstant(
    value.recoveryPointAt,
    "input.window.recoveryPointAt",
  );
  assertInteger(
    value.maxRpoSeconds,
    "input.window.maxRpoSeconds",
    0,
    31_536_000,
  );
  assertInteger(
    value.maxRtoSeconds,
    "input.window.maxRtoSeconds",
    1,
    31_536_000,
  );
  const observedRpoSeconds = exactSeconds(
    incidentCutoffAt - recoveryPointAt,
    "recovery point must not be after the incident cutoff",
  );
  const observedRtoSeconds = exactSeconds(
    completedAt - startedAt,
    "drill completion must be after drill start",
  );
  if (incidentCutoffAt > completedAt) {
    throw new Error("the incident cutoff must not be after drill completion");
  }
  if (observedRpoSeconds > value.maxRpoSeconds) {
    throw new Error("the observed recovery point exceeds the approved RPO");
  }
  if (observedRtoSeconds > value.maxRtoSeconds) {
    throw new Error("the observed restore duration exceeds the approved RTO");
  }
  return {
    startedAt: value.startedAt,
    completedAt: value.completedAt,
    incidentCutoffAt: value.incidentCutoffAt,
    recoveryPointAt: value.recoveryPointAt,
    maxRpoSeconds: value.maxRpoSeconds,
    maxRtoSeconds: value.maxRtoSeconds,
    observedRpoSeconds,
    observedRtoSeconds,
  };
}

function validateDatabase(value) {
  assertRecord(value, "input.database");
  assertExactKeys(
    value,
    [
      "foreignKeysValid",
      "forcedRls",
      "postgresVersion",
      "runtimeRolesBypassRls",
      "schemaCompatible",
    ],
    "input.database",
  );
  assertBoundedString(
    value.postgresVersion,
    "input.database.postgresVersion",
    /^18\.\d{1,3}$/u,
  );
  assertRequiredBoolean(
    value.schemaCompatible,
    true,
    "input.database.schemaCompatible",
  );
  assertRequiredBoolean(value.forcedRls, true, "input.database.forcedRls");
  assertRequiredBoolean(
    value.runtimeRolesBypassRls,
    false,
    "input.database.runtimeRolesBypassRls",
  );
  assertRequiredBoolean(
    value.foreignKeysValid,
    true,
    "input.database.foreignKeysValid",
  );
  return { ...value };
}

function validateAudit(value) {
  assertRecord(value, "input.audit");
  assertExactKeys(
    value,
    [
      "platformChainValid",
      "tenantChainsChecked",
      "tenantChainsValid",
      "trustedCheckpointSha256",
    ],
    "input.audit",
  );
  assertInteger(
    value.tenantChainsChecked,
    "input.audit.tenantChainsChecked",
    1,
    1_000_000,
  );
  assertRequiredBoolean(
    value.tenantChainsValid,
    true,
    "input.audit.tenantChainsValid",
  );
  assertRequiredBoolean(
    value.platformChainValid,
    true,
    "input.audit.platformChainValid",
  );
  assertDigest(
    value.trustedCheckpointSha256,
    "input.audit.trustedCheckpointSha256",
  );
  return { ...value };
}

function validateStorage(value) {
  assertRecord(value, "input.storage");
  assertExactKeys(
    value,
    [
      "inventorySha256",
      "missingObjects",
      "objectCount",
      "sampledObjectHashesValid",
    ],
    "input.storage",
  );
  assertDigest(value.inventorySha256, "input.storage.inventorySha256");
  assertInteger(
    value.objectCount,
    "input.storage.objectCount",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  assertInteger(
    value.missingObjects,
    "input.storage.missingObjects",
    0,
    Number.MAX_SAFE_INTEGER,
  );
  if (value.missingObjects !== 0) {
    throw new Error("the recovered object inventory contains missing objects");
  }
  assertRequiredBoolean(
    value.sampledObjectHashesValid,
    true,
    "input.storage.sampledObjectHashesValid",
  );
  return { ...value };
}

function validateAcceptance(value) {
  assertRecord(value, "input.acceptance");
  const keys = [
    "crossTenantDenied",
    "notifierPaused",
    "outboxPaused",
    "readinessPassed",
    "workerPaused",
  ];
  assertExactKeys(value, keys, "input.acceptance");
  for (const key of keys) {
    assertRequiredBoolean(value[key], true, `input.acceptance.${key}`);
  }
  return { ...value };
}

async function hashEvidenceFiles(value) {
  if (
    !Array.isArray(value) ||
    value.length < REQUIRED_EVIDENCE_LABELS.size ||
    value.length > 64
  ) {
    throw new Error("input.evidenceFiles must contain between 6 and 64 files");
  }
  const labels = new Set();
  const results = [];
  for (const [index, item] of value.entries()) {
    const field = `input.evidenceFiles[${index}]`;
    assertRecord(item, field);
    assertExactKeys(item, ["label", "path"], field);
    assertBoundedString(
      item.label,
      `${field}.label`,
      /^[a-z][a-z0-9-]{0,63}$/u,
    );
    if (labels.has(item.label))
      throw new Error("evidence labels must be unique");
    labels.add(item.label);
    assertBoundedString(item.path, `${field}.path`, /^.{1,4096}$/u);
    if (!isAbsolute(item.path)) {
      throw new Error(`${field}.path must be absolute`);
    }
    const digest = await hashBoundedFile(item.path, item.label);
    results.push({ label: item.label, ...digest });
  }
  for (const required of REQUIRED_EVIDENCE_LABELS) {
    if (!labels.has(required)) {
      throw new Error(`required evidence label is missing: ${required}`);
    }
  }
  return results.sort((left, right) => compareAscii(left.label, right.label));
}

function validateManifest(value) {
  assertRecord(value, "manifest");
  assertExactKeys(
    value,
    [
      "acceptance",
      "audit",
      "database",
      "drillId",
      "environment",
      "evidence",
      "release",
      "schemaVersion",
      "storage",
      "window",
    ],
    "manifest",
  );
  if (value.schemaVersion !== 1)
    throw new Error("unsupported recovery evidence manifest");
  assertUuid(value.drillId, "manifest.drillId");
  assertBoundedString(
    value.environment,
    "manifest.environment",
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u,
  );
  validateRelease(value.release);
  validateDatabase(value.database);
  validateAudit(value.audit);
  validateStorage(value.storage);
  validateAcceptance(value.acceptance);
  validateManifestWindow(value.window);
  validateManifestEvidence(value.evidence);
}

function validateManifestWindow(value) {
  assertRecord(value, "manifest.window");
  assertExactKeys(
    value,
    [
      "completedAt",
      "incidentCutoffAt",
      "maxRpoSeconds",
      "maxRtoSeconds",
      "observedRpoSeconds",
      "observedRtoSeconds",
      "recoveryPointAt",
      "startedAt",
    ],
    "manifest.window",
  );
  const rebuilt = validateWindow({
    startedAt: value.startedAt,
    completedAt: value.completedAt,
    incidentCutoffAt: value.incidentCutoffAt,
    recoveryPointAt: value.recoveryPointAt,
    maxRpoSeconds: value.maxRpoSeconds,
    maxRtoSeconds: value.maxRtoSeconds,
  });
  if (
    value.observedRpoSeconds !== rebuilt.observedRpoSeconds ||
    value.observedRtoSeconds !== rebuilt.observedRtoSeconds
  ) {
    throw new Error("manifest recovery window calculations are inconsistent");
  }
}

function validateManifestEvidence(value) {
  if (
    !Array.isArray(value) ||
    value.length < REQUIRED_EVIDENCE_LABELS.size ||
    value.length > 64
  ) {
    throw new Error("manifest evidence must contain between 6 and 64 entries");
  }
  const labels = new Set();
  let previous = "";
  for (const [index, item] of value.entries()) {
    const field = `manifest.evidence[${index}]`;
    assertRecord(item, field);
    assertExactKeys(item, ["bytes", "label", "sha256"], field);
    assertBoundedString(
      item.label,
      `${field}.label`,
      /^[a-z][a-z0-9-]{0,63}$/u,
    );
    assertInteger(item.bytes, `${field}.bytes`, 1, MAX_EVIDENCE_BYTES);
    assertDigest(item.sha256, `${field}.sha256`);
    if (
      labels.has(item.label) ||
      (previous && compareAscii(previous, item.label) >= 0)
    ) {
      throw new Error("manifest evidence labels must be unique and sorted");
    }
    labels.add(item.label);
    previous = item.label;
  }
  for (const required of REQUIRED_EVIDENCE_LABELS) {
    if (!labels.has(required))
      throw new Error(`required evidence label is missing: ${required}`);
  }
}

async function hashBoundedFile(path, label) {
  const handle = await open(path, "r");
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.size < 1n ||
      before.size > BigInt(MAX_EVIDENCE_BYTES)
    ) {
      throw new Error(
        `evidence file ${label} must be a non-empty regular file no larger than 64 MiB`,
      );
    }
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      bytes += chunk.length;
      if (bytes > MAX_EVIDENCE_BYTES) {
        throw new Error(
          `evidence file ${label} exceeded the 64 MiB read boundary`,
        );
      }
      hash.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    if (BigInt(bytes) !== before.size || !sameFileSnapshot(before, after)) {
      throw new Error(`evidence file ${label} changed while it was hashed`);
    }
    return { bytes, sha256: hash.digest("hex") };
  } finally {
    await handle.close();
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortJson(value[key])]),
    );
  }
  return value;
}

function compareAscii(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameFileSnapshot(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function assertJsonComplexity(value) {
  const pending = [{ depth: 0, value }];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    nodes += 1;
    if (nodes > 20_000 || current.depth > 32) {
      throw new Error("JSON input exceeds the depth or node boundary");
    }
    if (current.value !== null && typeof current.value === "object") {
      for (const child of Object.values(current.value)) {
        pending.push({ depth: current.depth + 1, value: child });
      }
    }
  }
}

function assertRecord(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
}

function assertExactKeys(value, expected, field) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${field} contains missing or unsupported fields`);
  }
}

function assertBoundedString(value, field, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${field} is invalid`);
  }
}

function assertUuid(value, field) {
  assertBoundedString(
    value,
    field,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
}

function assertDigest(value, field) {
  assertBoundedString(value, field, /^[0-9a-f]{64}$/u);
}

function assertInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${field} is outside its accepted integer range`);
  }
}

function assertRequiredBoolean(value, expected, field) {
  if (value !== expected) throw new Error(`${field} must be ${expected}`);
}

function parseInstant(value, field) {
  assertBoundedString(
    value,
    field,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u,
  );
  const parsed = Date.parse(value);
  if (
    !Number.isFinite(parsed) ||
    new Date(parsed).toISOString() !== normalizeMilliseconds(value)
  ) {
    throw new Error(`${field} is not a canonical UTC instant`);
  }
  return parsed;
}

function normalizeMilliseconds(value) {
  return value.includes(".") ? value : value.replace("Z", ".000Z");
}

function exactSeconds(milliseconds, negativeMessage) {
  if (milliseconds < 0) throw new Error(negativeMessage);
  if (milliseconds % 1000 !== 0)
    throw new Error("recovery evidence instants must align to seconds");
  return milliseconds / 1000;
}

function parseOptions(argumentsList) {
  if (argumentsList.length % 2 !== 0)
    throw new Error("every option requires a value");
  const options = {};
  for (let index = 0; index < argumentsList.length; index += 2) {
    const name = argumentsList[index];
    const value = argumentsList[index + 1];
    if (
      !name?.startsWith("--") ||
      name.length < 3 ||
      !value ||
      value.startsWith("--")
    ) {
      throw new Error("invalid command option");
    }
    const key = name.slice(2);
    if (Object.hasOwn(options, key))
      throw new Error(`duplicate option: ${name}`);
    options[key] = value;
  }
  return options;
}

function requireOptions(options, expected) {
  const actual = Object.keys(options).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(
      `required options: ${wanted.map((key) => `--${key}`).join(", ")}`,
    );
  }
}

async function readJson(path, maximum, label) {
  const bytes = await readBoundedFile(path, maximum, label);
  const text = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  assertJsonComplexity(value);
  if (canonicalJson(value) !== text) {
    throw new Error(
      `${label} must use canonical JSON with sorted keys and no duplicate fields`,
    );
  }
  return value;
}

async function readBoundedFile(path, maximum, label) {
  const handle = await open(path, "r");
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(maximum)) {
      throw new Error(
        `${label} must be a regular file no larger than ${maximum} bytes`,
      );
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      BigInt(bytes.length) !== before.size ||
      !sameFileSnapshot(before, after)
    ) {
      throw new Error(`${label} changed while it was read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function writePairExclusive(
  firstPath,
  firstBytes,
  secondPath,
  secondBytes,
) {
  let firstHandle;
  let secondHandle;
  try {
    firstHandle = await open(firstPath, "wx", 0o640);
    secondHandle = await open(secondPath, "wx", 0o640);
    await firstHandle.writeFile(firstBytes);
    await secondHandle.writeFile(secondBytes);
    await firstHandle.sync();
    await secondHandle.sync();
  } catch (error) {
    await firstHandle?.close().catch(() => {});
    await secondHandle?.close().catch(() => {});
    if (firstHandle) await unlink(firstPath).catch(() => {});
    if (secondHandle) await unlink(secondPath).catch(() => {});
    throw error;
  }
  await firstHandle.close();
  await secondHandle.close();
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    const message =
      error instanceof Error
        ? error.message
        : "unknown recovery evidence error";
    process.stderr.write(`recovery evidence failed: ${message}\n`);
    process.exitCode = 1;
  });
}
