import { randomBytes } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import { link, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";

const disposableDatabasePattern =
  /^periapsis_performance_[0-9]{13}_[0-9a-f]{12}$/;

export function parseLocalAdminUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
    throw new TypeError("PERIAPSIS_PERFORMANCE_ADMIN_URL is required");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("performance admin URL is invalid");
  }
  if (!new Set(["postgres:", "postgresql:"]).has(parsed.protocol)) {
    throw new TypeError("performance admin URL must use PostgreSQL");
  }
  if (!new Set(["127.0.0.1", "[::1]"]).has(parsed.hostname)) {
    throw new TypeError(
      "performance admin URL must use a numeric loopback address",
    );
  }
  if (
    parsed.username === "" ||
    !/^\/[A-Za-z0-9_.-]{1,63}$/.test(parsed.pathname)
  ) {
    throw new TypeError("performance admin URL must name a user and database");
  }
  if (parsed.hash !== "") {
    throw new TypeError("performance admin URL must not contain a fragment");
  }
  const options = [...parsed.searchParams.entries()];
  if (
    options.some(
      ([key, queryValue]) => key !== "sslmode" || queryValue !== "disable",
    ) ||
    options.length > 1
  ) {
    throw new TypeError(
      "performance admin URL only permits sslmode=disable on loopback",
    );
  }
  return parsed;
}

export function preflightPsqlExecutable(
  value,
  {
    platformName = process.platform,
    realpathImplementation = realpathSync.native,
    statImplementation = statSync,
  } = {},
) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    value !== value.trim() ||
    !isAbsolute(value) ||
    typeof realpathImplementation !== "function" ||
    typeof statImplementation !== "function"
  ) {
    throw new TypeError("PERIAPSIS_PERFORMANCE_PSQL must be an absolute path");
  }
  let canonical;
  let facts;
  try {
    canonical = realpathImplementation(value);
    facts = statImplementation(value);
  } catch (error) {
    throw new Error("PostgreSQL psql executable is unavailable", {
      cause: error,
    });
  }
  const expectedName = platformName === "win32" ? "psql.exe" : "psql";
  if (
    typeof canonical !== "string" ||
    canonical.length === 0 ||
    basename(canonical).toLowerCase() !== expectedName ||
    typeof facts?.isFile !== "function" ||
    !facts.isFile()
  ) {
    throw new Error("PostgreSQL psql executable boundary is invalid");
  }
  return canonical;
}

export function createDisposableDatabaseName(now = Date.now(), entropy) {
  if (!Number.isSafeInteger(now) || now < 1_000_000_000_000) {
    throw new TypeError("performance database timestamp is invalid");
  }
  const suffix = entropy ?? randomBytes(6).toString("hex");
  const name = `periapsis_performance_${now}_${suffix}`;
  assertDisposableDatabaseName(name);
  return name;
}

export function assertDisposableDatabaseName(name) {
  if (typeof name !== "string" || !disposableDatabasePattern.test(name)) {
    throw new TypeError("refusing to mutate a non-disposable database name");
  }
  return name;
}

export function databaseUrl(adminUrl, databaseName) {
  assertDisposableDatabaseName(databaseName);
  const target = new URL(adminUrl.href);
  target.pathname = `/${databaseName}`;
  return target.href;
}

function decodeUrlCredential(value, label) {
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new TypeError(`${label} is malformed`);
  }
  if (
    decoded.length > 1024 ||
    [...decoded].some((character) => {
      const code = character.codePointAt(0);
      return code <= 31 || code === 127;
    })
  ) {
    throw new TypeError(`${label} is malformed`);
  }
  return decoded;
}

function pgPassField(value) {
  return value.replaceAll("\\", "\\\\").replaceAll(":", "\\:");
}

export function passwordlessConnectionUrl(connectionUrl) {
  const parsed = parseLocalAdminUrl(
    connectionUrl instanceof URL ? connectionUrl.href : connectionUrl,
  );
  parsed.password = "";
  return parsed.href;
}

export function pgPassEntry(connectionUrl) {
  const parsed = parseLocalAdminUrl(
    connectionUrl instanceof URL ? connectionUrl.href : connectionUrl,
  );
  const username = decodeUrlCredential(parsed.username, "PostgreSQL username");
  const password = decodeUrlCredential(parsed.password, "PostgreSQL password");
  if (password === "") {
    return null;
  }
  const hostname = parsed.hostname.startsWith("[")
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname;
  return `${pgPassField(hostname)}:${parsed.port || "5432"}:*:${pgPassField(username)}:${pgPassField(password)}\n`;
}

export function assertPostgresVersion(versionNumber, versionText) {
  if (
    versionNumber !== "180006" ||
    typeof versionText !== "string" ||
    !/^18\.6(?:\s|$)/.test(versionText)
  ) {
    throw new Error(
      `performance gates require PostgreSQL 18.6; received ${String(versionText)}`,
    );
  }
}

export function mergeShutdownFailure(existingFailure, signal) {
  if (signal === null) {
    return existingFailure;
  }
  if (!new Set(["SIGINT", "SIGTERM"]).has(signal)) {
    throw new TypeError("performance shutdown signal is invalid");
  }
  const signalFailure = new Error(
    `performance gate received ${signal}; cleanup was required`,
  );
  if (existingFailure === undefined || existingFailure === null) {
    return signalFailure;
  }
  if (!(existingFailure instanceof Error)) {
    throw new TypeError("performance shutdown failure is malformed");
  }
  return new AggregateError(
    [existingFailure, signalFailure],
    "performance gate failed and received a shutdown signal",
    { cause: existingFailure },
  );
}

export function catchableShutdownSignals(platformName = process.platform) {
  if (platformName === "win32") {
    // Node can observe a console Ctrl+C event as SIGINT on Windows. Its
    // process.kill()/TerminateProcess implementation for SIGINT/SIGTERM is a
    // forced termination and does not invoke JavaScript signal handlers.
    return Object.freeze(["SIGINT"]);
  }
  if (
    new Set(["aix", "darwin", "freebsd", "linux", "openbsd", "sunos"]).has(
      platformName,
    )
  ) {
    return Object.freeze(["SIGINT", "SIGTERM"]);
  }
  throw new Error("performance shutdown platform is unsupported");
}

export function createShutdownLatch(onFirstSignal) {
  if (typeof onFirstSignal !== "function") {
    throw new TypeError("performance shutdown callback is invalid");
  }
  let signal = null;
  return Object.freeze({
    get signal() {
      return signal;
    },
    handle(nextSignal) {
      if (!new Set(["SIGINT", "SIGTERM"]).has(nextSignal)) {
        throw new TypeError("performance shutdown signal is invalid");
      }
      if (signal === null) {
        signal = nextSignal;
        onFirstSignal(nextSignal);
      }
      return signal;
    },
  });
}

export function createRecoveredCleanupError(failures, cleanupEvidence) {
  if (
    !Array.isArray(failures) ||
    failures.length === 0 ||
    !failures.every((error) => error instanceof Error) ||
    typeof cleanupEvidence !== "object" ||
    cleanupEvidence === null ||
    Array.isArray(cleanupEvidence) ||
    cleanupEvidence.finalDatabaseCount !== 0 ||
    cleanupEvidence.status !== "recovered_failed"
  ) {
    throw new TypeError("recovered cleanup evidence is malformed");
  }
  const error = new AggregateError(
    failures,
    "disposable database cleanup recovered from an uncertain DROP",
    { cause: failures[0] },
  );
  Object.defineProperty(error, "cleanupEvidence", {
    configurable: false,
    enumerable: false,
    value: cleanupEvidence,
    writable: false,
  });
  return error;
}

export function blockedCleanupIdentifiers(
  activePsqlPids,
  activeProcessTreePids,
  credentialDirectoryBasename,
) {
  const pidLists = [activePsqlPids, activeProcessTreePids];
  if (
    pidLists.some(
      (pids) =>
        !Array.isArray(pids) ||
        pids.length > 64 ||
        !pids.every(
          (pid) => Number.isSafeInteger(pid) && pid > 0 && pid <= 4_294_967_295,
        ) ||
        new Set(pids).size !== pids.length,
    ) ||
    (credentialDirectoryBasename !== null &&
      (typeof credentialDirectoryBasename !== "string" ||
        !/^periapsis-performance-pgpass-[A-Za-z0-9_-]{1,128}$/.test(
          credentialDirectoryBasename,
        )))
  ) {
    throw new TypeError("blocked cleanup identifiers are malformed");
  }
  return Object.freeze({
    activeProcessTreePids: Object.freeze(
      [...activeProcessTreePids].toSorted((a, b) => a - b),
    ),
    activePsqlPids: Object.freeze(
      [...activePsqlPids].toSorted((a, b) => a - b),
    ),
    credentialDirectoryBasename,
  });
}

export function parseWindowsIdentitySid(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) {
    throw new TypeError("Windows credential identity is malformed");
  }
  const match =
    /^"(?:""|[^"\r\n]){1,512}","(S-1-(?:[0-9]+-){1,14}[0-9]+)"\r?\n?$/.exec(
      value,
    );
  if (match === null) {
    throw new TypeError("Windows credential identity is malformed");
  }
  return match[1];
}

export async function publishFileNoReplace(
  staging,
  target,
  { unlinkImplementation = unlink } = {},
) {
  if (
    typeof staging !== "string" ||
    typeof target !== "string" ||
    staging.length === 0 ||
    target.length === 0 ||
    resolve(staging) === resolve(target) ||
    dirname(resolve(staging)) !== dirname(resolve(target)) ||
    typeof unlinkImplementation !== "function"
  ) {
    throw new TypeError("immutable file publication boundary is malformed");
  }
  await link(staging, target);
  try {
    await unlinkImplementation(staging);
    return Object.freeze({ stagingRemoved: true });
  } catch {
    // The final no-replace link is already a complete, fsynced commit. A
    // second link to the same inode is harmless and must not invert the gate
    // result recorded in the immutable target.
    return Object.freeze({ stagingRemoved: false });
  }
}

export function assertFreshClusterFacts(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("performance cluster preflight is malformed");
  }
  const databaseNames = value.nonTemplateDatabases;
  if (
    value.currentDatabase !== "postgres" ||
    value.currentUserIsSuperuser !== true ||
    !new Set(["127.0.0.1", "::1"]).has(value.serverAddress) ||
    value.serverTimezone !== "UTC" ||
    value.databaseRoleSettingCount !== 0 ||
    !Array.isArray(databaseNames) ||
    databaseNames.length !== 1 ||
    databaseNames[0] !== "postgres" ||
    value.userRelationCount !== 0 ||
    value.existingPeriapsisRoles !== 0 ||
    value.existingDisposableDatabases !== 0
  ) {
    throw new Error(
      "performance gates require a fresh disposable PostgreSQL cluster with server timezone UTC and no database/role settings",
    );
  }
  return Object.freeze({
    currentDatabase: value.currentDatabase,
    currentUserIsSuperuser: value.currentUserIsSuperuser,
    serverAddress: value.serverAddress,
    serverTimezone: value.serverTimezone,
    databaseRoleSettingCount: value.databaseRoleSettingCount,
    existingDisposableDatabases: value.existingDisposableDatabases,
    existingPeriapsisRoles: value.existingPeriapsisRoles,
    nonTemplateDatabases: Object.freeze([...databaseNames]),
    userRelationCount: value.userRelationCount,
  });
}

export function assertExpectedClusterDataDirectory(
  expectedDirectory,
  observedDirectory,
  {
    platformName = process.platform,
    realpathImplementation = realpathSync.native,
    statImplementation = statSync,
  } = {},
) {
  if (
    typeof expectedDirectory !== "string" ||
    expectedDirectory.length === 0 ||
    expectedDirectory.length > 4096 ||
    expectedDirectory !== expectedDirectory.trim() ||
    !isAbsolute(expectedDirectory) ||
    typeof observedDirectory !== "string" ||
    observedDirectory.length === 0 ||
    observedDirectory.length > 4096 ||
    !isAbsolute(observedDirectory) ||
    typeof realpathImplementation !== "function" ||
    typeof statImplementation !== "function"
  ) {
    throw new TypeError("performance cluster data-directory pin is malformed");
  }
  let canonicalExpected;
  let canonicalObserved;
  let facts;
  try {
    canonicalExpected = realpathImplementation(expectedDirectory);
    canonicalObserved = realpathImplementation(observedDirectory);
    facts = statImplementation(expectedDirectory);
  } catch (error) {
    throw new Error("performance cluster data-directory pin is unavailable", {
      cause: error,
    });
  }
  const normalize =
    platformName === "win32"
      ? (value) => resolve(value).toLowerCase()
      : (value) => resolve(value);
  if (
    typeof facts?.isDirectory !== "function" ||
    !facts.isDirectory() ||
    normalize(canonicalExpected) !== normalize(canonicalObserved)
  ) {
    throw new Error("connected PostgreSQL data directory differs from the pin");
  }
  return Object.freeze({ pinned: true });
}

export function assertOwnedBackendSettlement(value) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).toSorted().join(",") !==
      "matched,remaining,terminated" ||
    !Number.isSafeInteger(value.matched) ||
    value.matched < 0 ||
    value.matched > 1 ||
    !Number.isSafeInteger(value.terminated) ||
    value.terminated < 0 ||
    value.terminated > value.matched ||
    value.remaining !== 0
  ) {
    throw new Error("owned PostgreSQL backend did not quiesce safely");
  }
  return Object.freeze({
    matched: value.matched,
    remaining: value.remaining,
    terminated: value.terminated,
  });
}

export function parseMigrationManifest(source) {
  if (typeof source !== "string" || source.length > 2 * 1024 * 1024) {
    throw new TypeError("migration manifest source is malformed");
  }
  const countMatches = [
    ...source.matchAll(/export const expectedMigrationCount = ([0-9]+);/g),
  ];
  const createdAtMatches = [
    ...source.matchAll(/export const expectedMigrationCreatedAt = ([0-9]+);/g),
  ];
  const hashMatches = [
    ...source.matchAll(
      /export const expectedMigrationHash =\s*"([0-9a-f]{64})";/g,
    ),
  ];
  const fingerprintMatches = [
    ...source.matchAll(
      /export const expectedMigrationFingerprint =\s*"([0-9a-f@:]+)";/g,
    ),
  ];
  if (
    countMatches.length !== 1 ||
    createdAtMatches.length !== 1 ||
    hashMatches.length !== 1 ||
    fingerprintMatches.length !== 1
  ) {
    throw new TypeError("migration manifest pin is missing or ambiguous");
  }
  const count = Number(countMatches[0][1]);
  const createdAt = Number(createdAtMatches[0][1]);
  if (
    !Number.isSafeInteger(count) ||
    count < 1 ||
    count > 10_000 ||
    !Number.isSafeInteger(createdAt) ||
    createdAt < 1_000_000_000_000
  ) {
    throw new TypeError("migration manifest pin is out of bounds");
  }
  const fingerprint = fingerprintMatches[0][1];
  const fingerprintEntries = fingerprint.split(":");
  if (
    fingerprintEntries.length !== count ||
    !fingerprintEntries.every((entry) =>
      /^[0-9]{13}@[0-9a-f]{64}$/.test(entry),
    ) ||
    fingerprintEntries.at(-1) !== `${createdAt}@${hashMatches[0][1]}`
  ) {
    throw new TypeError("migration manifest fingerprint is malformed");
  }
  return Object.freeze({
    count,
    createdAt,
    fingerprint,
    hash: hashMatches[0][1],
  });
}

export function redactConnectionText(value, urls = []) {
  let redacted = String(value ?? "");
  for (const candidate of urls) {
    if (candidate instanceof URL) {
      redacted = redacted.replaceAll(candidate.href, "[REDACTED_DATABASE_URL]");
      if (candidate.password !== "") {
        redacted = redacted.replaceAll(candidate.password, "[REDACTED]");
        try {
          redacted = redacted.replaceAll(
            decodeURIComponent(candidate.password),
            "[REDACTED]",
          );
        } catch {
          // The exact URL and encoded password were already removed.
        }
      }
    }
  }
  return redacted;
}

export function sanitizedPostgresEnvironment(environment, overrides = {}) {
  if (
    typeof environment !== "object" ||
    environment === null ||
    Array.isArray(environment) ||
    typeof overrides !== "object" ||
    overrides === null ||
    Array.isArray(overrides)
  ) {
    throw new TypeError("PostgreSQL subprocess environment is malformed");
  }
  const result = {};
  const permittedOverrides = new Set([
    "DATABASE_URL",
    "PGAPPNAME",
    "PGCONNECT_TIMEOUT",
    "PGPASSFILE",
    "PERIAPSIS_PERFORMANCE_DATABASE_URL_FILE",
    "PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY",
  ]);
  for (const [key, value] of Object.entries(environment)) {
    const normalizedKey = key.toUpperCase();
    if (
      normalizedKey !== "DATABASE_URL" &&
      normalizedKey !== "DATABASE_URL_FILE" &&
      !normalizedKey.startsWith("PG") &&
      !normalizedKey.startsWith("PERIAPSIS_PERFORMANCE_") &&
      typeof value === "string"
    ) {
      result[key] = value;
    }
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (!permittedOverrides.has(key) || typeof value !== "string") {
      throw new TypeError("PostgreSQL subprocess override is malformed");
    }
    result[key] = value;
  }
  return result;
}
