import assert from "node:assert/strict";
import { lstat } from "node:fs/promises";
import test from "node:test";

import {
  credentialFromPreparationError,
  postgresCredentialDirectoryBasename,
  preparePostgresCredential,
  removePostgresCredential,
} from "../../scripts/performance/postgres-credential.mjs";

function injectedFilesystemFailure(message) {
  const error = new Error(message);
  error.code = "EACCES";
  return error;
}

test("post-write setup failure preserves bounded credential recovery evidence", async () => {
  let credential;
  try {
    await assert.rejects(
      preparePostgresCredential(
        "postgres://postgres:x@127.0.0.1/postgres?sslmode=disable",
        {
          removeOptions: {
            rmdirImplementation: async () => {
              throw injectedFilesystemFailure("injected directory failure");
            },
            unlinkImplementation: async () => {
              throw injectedFilesystemFailure("injected unlink failure");
            },
          },
          restrictPath: async (_path, isDirectory) => {
            if (!isDirectory) {
              throw new Error("injected post-write ACL failure");
            }
          },
        },
      ),
      (error) => {
        credential = credentialFromPreparationError(error);
        assert.ok(credential);
        assert.deepEqual(error.credentialCleanupEvidence, {
          directoryBasename: postgresCredentialDirectoryBasename(credential),
          status: "failed",
        });
        assert.match(error.message, /setup and cleanup failed/);
        assert.doesNotMatch(
          JSON.stringify(error.credentialCleanupEvidence),
          /postgres:\/\//,
        );
        return true;
      },
    );
    assert.equal((await lstat(credential.file)).isFile(), true);
    const cleanup = await removePostgresCredential(credential);
    assert.deepEqual(cleanup, {
      directoryBasename: postgresCredentialDirectoryBasename(credential),
      status: "removed",
    });
    assert.deepEqual(await removePostgresCredential(credential), {
      directoryBasename: postgresCredentialDirectoryBasename(credential),
      status: "not_present",
    });
  } finally {
    if (credential !== undefined) {
      await removePostgresCredential(credential).catch(() => undefined);
    }
  }
});
