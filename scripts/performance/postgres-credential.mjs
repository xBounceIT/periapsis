import { Buffer } from "node:buffer";
import { lstat, mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { pgPassEntry } from "./harness-safety.mjs";

const credentialDirectoryPrefix = "periapsis-performance-pgpass-";

function assertTemporaryCredentialDirectory(directory) {
  const normalized = resolve(directory);
  if (
    dirname(normalized) !== resolve(tmpdir()) ||
    !basename(normalized).startsWith(credentialDirectoryPrefix)
  ) {
    throw new Error(
      "temporary PostgreSQL credential path escaped its boundary",
    );
  }
  return normalized;
}

function assertCredentialBoundary(credential) {
  if (
    typeof credential !== "object" ||
    credential === null ||
    Array.isArray(credential)
  ) {
    throw new TypeError("temporary PostgreSQL credential is malformed");
  }
  const directory = assertTemporaryCredentialDirectory(credential.directory);
  const file = resolve(credential.file);
  if (dirname(file) !== directory || basename(file) !== "pgpass.conf") {
    throw new Error(
      "temporary PostgreSQL credential file escaped its boundary",
    );
  }
  return Object.freeze({ directory, file });
}

function attachCredential(error, credential, cleanupEvidence) {
  const sourceError =
    error instanceof Error
      ? error
      : new Error("PostgreSQL credential operation failed");
  const wrapped = new AggregateError(
    [sourceError],
    "PostgreSQL credential setup failed",
    { cause: sourceError },
  );
  Object.defineProperties(wrapped, {
    credentialCleanupEvidence: {
      configurable: false,
      enumerable: false,
      value: cleanupEvidence,
      writable: false,
    },
    postgresCredential: {
      configurable: false,
      enumerable: false,
      value: credential,
      writable: false,
    },
  });
  return wrapped;
}

export function credentialFromPreparationError(error) {
  if (!(error instanceof Error) || error.postgresCredential === undefined) {
    return null;
  }
  return assertCredentialBoundary(error.postgresCredential);
}

export function postgresCredentialDirectoryBasename(credential) {
  if (credential === null) {
    return null;
  }
  return basename(assertCredentialBoundary(credential).directory);
}

export async function removePostgresCredential(
  credential,
  { rmdirImplementation = rmdir, unlinkImplementation = unlink } = {},
) {
  if (credential === null) {
    return Object.freeze({ directoryBasename: null, status: "not_required" });
  }
  if (
    typeof rmdirImplementation !== "function" ||
    typeof unlinkImplementation !== "function"
  ) {
    throw new TypeError("PostgreSQL credential cleanup boundary is malformed");
  }
  const validated = assertCredentialBoundary(credential);
  const failures = [];
  let removedSomething = false;
  try {
    await unlinkImplementation(validated.file);
    removedSomething = true;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      failures.push(
        error instanceof Error ? error : new Error("credential unlink failed"),
      );
    }
  }
  try {
    await rmdirImplementation(validated.directory);
    removedSomething = true;
  } catch (error) {
    if (error?.code !== "ENOENT") {
      failures.push(
        error instanceof Error
          ? error
          : new Error("credential directory removal failed"),
      );
    }
  }
  const evidence = Object.freeze({
    directoryBasename: basename(validated.directory),
    status:
      failures.length === 0
        ? removedSomething
          ? "removed"
          : "not_present"
        : "failed",
  });
  if (failures.length > 0) {
    const cleanupError = new AggregateError(
      failures,
      "temporary PostgreSQL credential cleanup failed",
      { cause: failures[0] },
    );
    Object.defineProperty(cleanupError, "credentialCleanupEvidence", {
      configurable: false,
      enumerable: false,
      value: evidence,
      writable: false,
    });
    throw cleanupError;
  }
  return evidence;
}

export async function preparePostgresCredential(
  connectionUrl,
  {
    lstatImplementation = lstat,
    makeDirectoryImplementation = mkdtemp,
    removeOptions,
    restrictPath,
    writeFileImplementation = writeFile,
  } = {},
) {
  const entry = pgPassEntry(connectionUrl);
  if (entry === null) {
    return null;
  }
  if (
    typeof lstatImplementation !== "function" ||
    typeof makeDirectoryImplementation !== "function" ||
    typeof restrictPath !== "function" ||
    typeof writeFileImplementation !== "function"
  ) {
    throw new TypeError("PostgreSQL credential setup boundary is malformed");
  }
  const directory = assertTemporaryCredentialDirectory(
    await makeDirectoryImplementation(
      join(tmpdir(), credentialDirectoryPrefix),
    ),
  );
  const credential = Object.freeze({
    directory,
    file: join(directory, "pgpass.conf"),
  });
  try {
    await restrictPath(credential.directory, true);
    await writeFileImplementation(credential.file, entry, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await restrictPath(credential.file, false);
    const facts = await lstatImplementation(credential.file);
    if (!facts.isFile() || facts.size !== Buffer.byteLength(entry)) {
      throw new Error("temporary PostgreSQL credential file is malformed");
    }
    return credential;
  } catch (error) {
    try {
      const cleanupEvidence = await removePostgresCredential(
        credential,
        removeOptions,
      );
      throw attachCredential(error, credential, cleanupEvidence);
    } catch (cleanupError) {
      if (cleanupError?.postgresCredential !== undefined) {
        throw cleanupError;
      }
      const sourceError =
        error instanceof Error ? error : new Error("credential setup failed");
      const combined = new AggregateError(
        [sourceError, cleanupError],
        "PostgreSQL credential setup and cleanup failed",
        { cause: sourceError },
      );
      Object.defineProperties(combined, {
        credentialCleanupEvidence: {
          configurable: false,
          enumerable: false,
          value:
            cleanupError?.credentialCleanupEvidence ??
            Object.freeze({
              directoryBasename: basename(directory),
              status: "failed",
            }),
          writable: false,
        },
        postgresCredential: {
          configurable: false,
          enumerable: false,
          value: credential,
          writable: false,
        },
      });
      throw combined;
    }
  }
}
