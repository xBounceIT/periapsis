import { Buffer } from "node:buffer";
import { lstat, mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { URL } from "node:url";

import {
  assertDisposableDatabaseName,
  parseLocalAdminUrl,
  pgPassEntry,
} from "./harness-safety.mjs";

const directoryPrefix = "periapsis-performance-sla-worker-";
const directoryPattern =
  /^periapsis-performance-sla-worker-[A-Za-z0-9_-]{1,128}$/;

function assertDirectory(directory) {
  if (typeof directory !== "string" || !isAbsolute(directory)) {
    throw new TypeError("temporary SLA worker credential path is malformed");
  }
  const normalized = resolve(directory);
  if (
    dirname(normalized) !== resolve(tmpdir()) ||
    !directoryPattern.test(basename(normalized))
  ) {
    throw new Error(
      "temporary SLA worker credential path escaped its boundary",
    );
  }
  return normalized;
}

function assertCredential(credential) {
  if (
    typeof credential !== "object" ||
    credential === null ||
    Array.isArray(credential) ||
    typeof credential.file !== "string" ||
    !isAbsolute(credential.file)
  ) {
    throw new TypeError("temporary SLA worker credential is malformed");
  }
  const directory = assertDirectory(credential.directory);
  const file = resolve(credential.file);
  if (dirname(file) !== directory || basename(file) !== "database-url.conf") {
    throw new Error(
      "temporary SLA worker credential file escaped its boundary",
    );
  }
  return Object.freeze({ directory, file });
}

function evidence(credential, status) {
  return Object.freeze({
    directoryBasename:
      credential === null ? null : basename(credential.directory),
    status,
  });
}

function operationError(message, credential, cleanupEvidence) {
  // Filesystem and ACL implementations may include the secret-bearing input in
  // their errors. Keep recovery metadata, never their message, stack or cause.
  const error = new Error(message);
  Object.defineProperties(error, {
    credentialCleanupEvidence: { value: cleanupEvidence },
    slaWorkerCredential: { value: credential },
  });
  return error;
}

export function slaWorkerCredentialFromPreparationError(error) {
  if (!(error instanceof Error) || error.slaWorkerCredential === undefined) {
    return null;
  }
  return assertCredential(error.slaWorkerCredential);
}

export function slaWorkerCredentialDirectoryBasename(credential) {
  return credential === null
    ? null
    : basename(assertCredential(credential).directory);
}

export async function removeSlaWorkerCredential(
  credential,
  {
    lstatImplementation = lstat,
    rmdirImplementation = rmdir,
    unlinkImplementation = unlink,
  } = {},
) {
  if (credential === null) {
    return evidence(null, "not_required");
  }
  if (
    typeof lstatImplementation !== "function" ||
    typeof rmdirImplementation !== "function" ||
    typeof unlinkImplementation !== "function"
  ) {
    throw new TypeError("SLA worker credential cleanup boundary is malformed");
  }
  const validated = assertCredential(credential);
  const fail = () =>
    operationError(
      "temporary SLA worker credential cleanup failed",
      validated,
      evidence(validated, "failed"),
    );
  try {
    const facts = await lstatImplementation(validated.directory);
    if (!facts.isDirectory() || facts.isSymbolicLink()) {
      throw fail();
    }
  } catch (error) {
    if (error?.code === "ENOENT") {
      return evidence(validated, "not_present");
    }
    throw fail();
  }
  let failed = false;
  try {
    await unlinkImplementation(validated.file);
  } catch (error) {
    failed = error?.code !== "ENOENT";
  }
  try {
    // Never recurse: an unexpected file leaves the directory for investigation.
    await rmdirImplementation(validated.directory);
  } catch (error) {
    failed ||= error?.code !== "ENOENT";
  }
  if (failed) {
    throw fail();
  }
  return evidence(validated, "removed");
}

export async function prepareSlaWorkerCredential(
  connectionUrl,
  {
    lstatImplementation = lstat,
    makeDirectoryImplementation = mkdtemp,
    removeOptions,
    restrictPath,
    writeFileImplementation = writeFile,
  } = {},
) {
  const value =
    connectionUrl instanceof URL ? connectionUrl.href : connectionUrl;
  if (
    typeof value !== "string" ||
    value !== value.trim() ||
    [...value].some((character) => {
      const code = character.codePointAt(0);
      return code <= 31 || code === 127;
    })
  ) {
    throw new TypeError("SLA worker database URL is malformed");
  }
  const parsed = parseLocalAdminUrl(value);
  assertDisposableDatabaseName(parsed.pathname.slice(1));
  // Reuse the strict decoded user/password validation even for trust auth.
  pgPassEntry(parsed);
  const entry = `${parsed.href}\n`;
  if (
    typeof lstatImplementation !== "function" ||
    typeof makeDirectoryImplementation !== "function" ||
    typeof restrictPath !== "function" ||
    typeof writeFileImplementation !== "function"
  ) {
    throw new TypeError("SLA worker credential setup boundary is malformed");
  }
  let directory;
  try {
    directory = assertDirectory(
      await makeDirectoryImplementation(join(tmpdir(), directoryPrefix)),
    );
  } catch {
    throw new Error("SLA worker credential directory creation failed");
  }
  const credential = Object.freeze({
    directory,
    file: join(directory, "database-url.conf"),
  });
  try {
    const directoryFacts = await lstatImplementation(directory);
    if (!directoryFacts.isDirectory() || directoryFacts.isSymbolicLink()) {
      throw new Error("temporary SLA worker credential directory is malformed");
    }
    await restrictPath(directory, true);
    await writeFileImplementation(credential.file, entry, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await restrictPath(credential.file, false);
    const facts = await lstatImplementation(credential.file);
    if (
      !facts.isFile() ||
      facts.isSymbolicLink() ||
      facts.size !== Buffer.byteLength(entry)
    ) {
      throw new Error("temporary SLA worker credential file is malformed");
    }
    return credential;
  } catch {
    let cleanupEvidence;
    try {
      cleanupEvidence = await removeSlaWorkerCredential(
        credential,
        removeOptions,
      );
    } catch {
      cleanupEvidence = evidence(credential, "failed");
    }
    throw operationError(
      cleanupEvidence.status === "failed"
        ? "SLA worker credential setup and cleanup failed"
        : "SLA worker credential setup failed",
      credential,
      cleanupEvidence,
    );
  }
}
