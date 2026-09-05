import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  rmdir,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import process from "node:process";
import test from "node:test";
import { inspect } from "node:util";

import {
  prepareSlaWorkerCredential,
  removeSlaWorkerCredential,
  slaWorkerCredentialDirectoryBasename,
  slaWorkerCredentialFromPreparationError,
} from "../../scripts/performance/sla-worker-credential.mjs";

const database = "periapsis_performance_1788633007211_4133d9e053e0";
const trustUrl = `postgres://postgres@127.0.0.1:55559/${database}?sslmode=disable`;
const passwordUrl = `postgresql://postgres:synthetic%3Apassword%5Cprobe@[::1]:55559/${database}?sslmode=disable`;

async function restrictPath(path, isDirectory) {
  await chmod(path, isDirectory ? 0o700 : 0o600);
}

function injectedFailure() {
  const error = new Error(`synthetic:password\\probe ${passwordUrl}`);
  error.code = "EACCES";
  return error;
}

function assertRedacted(error) {
  assert.doesNotMatch(
    inspect(error, { showHidden: true, depth: 8 }),
    /synthetic|postgres(?:ql)?:\/\//,
  );
}

for (const [name, url] of [
  ["trust", trustUrl],
  ["password", passwordUrl],
]) {
  test(`SLA worker ${name} credential is private, exclusive and removable`, async () => {
    let credential;
    const calls = [];
    try {
      credential = await prepareSlaWorkerCredential(url, {
        restrictPath: async (path, isDirectory) => {
          calls.push(isDirectory ? "restrict-directory" : "restrict-file");
          await restrictPath(path, isDirectory);
        },
        writeFileImplementation: async (file, entry, options) => {
          calls.push("write");
          assert.deepEqual(options, {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600,
          });
          await writeFile(file, entry, options);
        },
      });
      assert.deepEqual(calls, ["restrict-directory", "write", "restrict-file"]);
      assert.ok(Object.isFrozen(credential));
      assert.equal(basename(credential.file), "database-url.conf");
      assert.equal(await readFile(credential.file, "utf8"), `${url}\n`);
      assert.equal(
        slaWorkerCredentialDirectoryBasename(credential),
        basename(credential.directory),
      );
      assert.doesNotMatch(
        JSON.stringify(credential),
        /synthetic|postgres(?:ql)?:\/\//,
      );
      if (process.platform !== "win32") {
        assert.equal((await lstat(credential.directory)).mode & 0o777, 0o700);
        assert.equal((await lstat(credential.file)).mode & 0o777, 0o600);
      }
      assert.deepEqual(await removeSlaWorkerCredential(credential), {
        directoryBasename: basename(credential.directory),
        status: "removed",
      });
      assert.deepEqual(await removeSlaWorkerCredential(credential), {
        directoryBasename: basename(credential.directory),
        status: "not_present",
      });
    } finally {
      if (credential) await removeSlaWorkerCredential(credential);
    }
  });
}

test("invalid SLA worker connection boundaries fail before filesystem activity", async () => {
  const filesystemCalls = [];
  const urls = [
    trustUrl.replace(database, "postgres"),
    trustUrl.replace("127.0.0.1", "localhost"),
    trustUrl.replace("127.0.0.1", "192.0.2.1"),
    `${trustUrl}&host=192.0.2.1`,
    `${trustUrl}#fragment`,
    ` ${trustUrl}`,
    trustUrl.replace("postgres@", "postgres%00@"),
    trustUrl.replace("postgres@", "postgres:%0a@"),
    trustUrl.replace("postgres@", "postgres:%GG@"),
    trustUrl.replace("127.0.0.1", "127.\n0.0.1"),
  ];
  await Promise.all(
    urls.map((url) =>
      assert.rejects(
        prepareSlaWorkerCredential(url, {
          makeDirectoryImplementation: async () => {
            filesystemCalls.push("make-directory");
            throw injectedFailure();
          },
          restrictPath,
        }),
      ),
    ),
  );
  assert.deepEqual(filesystemCalls, []);
});

test("pre-write restriction failure removes the owned directory without exposing the cause", async () => {
  let credential;
  await assert.rejects(
    prepareSlaWorkerCredential(passwordUrl, {
      restrictPath: async () => {
        throw injectedFailure();
      },
      writeFileImplementation: async () =>
        assert.fail("must restrict before writing"),
    }),
    (error) => {
      credential = slaWorkerCredentialFromPreparationError(error);
      assert.ok(credential);
      assert.equal(error.credentialCleanupEvidence.status, "removed");
      assertRedacted(error);
      return true;
    },
  );
  await assert.rejects(lstat(credential.directory), { code: "ENOENT" });
});

test("post-write setup and cleanup failure preserves a retryable bounded handle", async () => {
  let credential;
  try {
    await assert.rejects(
      prepareSlaWorkerCredential(passwordUrl, {
        restrictPath: async (path, isDirectory) => {
          if (!isDirectory) throw injectedFailure();
          await restrictPath(path, true);
        },
        removeOptions: {
          unlinkImplementation: async () => {
            throw injectedFailure();
          },
          rmdirImplementation: async () => {
            throw injectedFailure();
          },
        },
      }),
      (error) => {
        credential = slaWorkerCredentialFromPreparationError(error);
        assert.ok(credential);
        assert.equal(error.credentialCleanupEvidence.status, "failed");
        assert.match(error.message, /setup and cleanup failed/);
        assertRedacted(error);
        return true;
      },
    );
    assert.equal(await readFile(credential.file, "utf8"), `${passwordUrl}\n`);
    assert.equal(
      (await removeSlaWorkerCredential(credential)).status,
      "removed",
    );
  } finally {
    if (credential) await removeSlaWorkerCredential(credential);
  }
});

test("credential cleanup is nonrecursive and retains unexpected files", async () => {
  const credential = await prepareSlaWorkerCredential(trustUrl, {
    restrictPath,
  });
  const extraFile = join(credential.directory, "unexpected.txt");
  try {
    await writeFile(extraFile, "synthetic marker", { flag: "wx" });
    await assert.rejects(removeSlaWorkerCredential(credential), (error) => {
      assert.equal(error.credentialCleanupEvidence.status, "failed");
      assertRedacted(error);
      return true;
    });
    assert.equal(await readFile(extraFile, "utf8"), "synthetic marker");
    await assert.rejects(lstat(credential.file), { code: "ENOENT" });
  } finally {
    await unlink(extraFile);
    await removeSlaWorkerCredential(credential);
  }
});

test("cleanup rejects escaped, relative and malformed paths before unlink", async () => {
  const directory = join(tmpdir(), "periapsis-performance-sla-worker-boundary");
  const filesystemCalls = [];
  const rejectedFilesystemCall = (operation) => async () => {
    filesystemCalls.push(operation);
    throw injectedFailure();
  };
  const credentials = [
    { directory: tmpdir(), file: join(tmpdir(), "database-url.conf") },
    { directory, file: join(directory, "..", "database-url.conf") },
    { directory, file: join(directory, "different.conf") },
    { directory: "relative", file: "database-url.conf" },
    {
      directory: join(tmpdir(), "periapsis-performance-sla-worker-"),
      file: join(directory, "database-url.conf"),
    },
    {},
    [],
  ];
  await Promise.all(
    credentials.map((credential) =>
      assert.rejects(
        removeSlaWorkerCredential(credential, {
          lstatImplementation: rejectedFilesystemCall("lstat"),
          unlinkImplementation: rejectedFilesystemCall("unlink"),
          rmdirImplementation: rejectedFilesystemCall("rmdir"),
        }),
      ),
    ),
  );
  await assert.rejects(
    prepareSlaWorkerCredential(trustUrl, {
      makeDirectoryImplementation: async () => tmpdir(),
      restrictPath: rejectedFilesystemCall("restrict"),
    }),
    /directory creation failed/,
  );
  assert.deepEqual(filesystemCalls, []);
  assert.equal(
    slaWorkerCredentialFromPreparationError(new Error("unrelated")),
    null,
  );
  assert.equal(slaWorkerCredentialDirectoryBasename(null), null);
  assert.deepEqual(await removeSlaWorkerCredential(null), {
    directoryBasename: null,
    status: "not_required",
  });
});

test("credential cleanup refuses a directory symlink without touching its target", async () => {
  const target = await mkdtemp(
    join(tmpdir(), "periapsis-sla-credential-target-"),
  );
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-performance-sla-worker-"),
  );
  const targetFile = join(target, "database-url.conf");
  await rmdir(directory);
  let linked = false;
  try {
    await writeFile(targetFile, "synthetic outside marker", { flag: "wx" });
    await symlink(
      target,
      directory,
      process.platform === "win32" ? "junction" : "dir",
    );
    linked = true;
    await assert.rejects(
      removeSlaWorkerCredential({
        directory,
        file: join(directory, "database-url.conf"),
      }),
      /cleanup failed/,
    );
    assert.equal(
      await readFile(targetFile, "utf8"),
      "synthetic outside marker",
    );
  } finally {
    if (linked) await unlink(directory);
    await unlink(targetFile);
    await rmdir(target);
  }
});

test("malformed post-write file facts retain cleanup evidence", async () => {
  await assert.rejects(
    prepareSlaWorkerCredential(trustUrl, {
      restrictPath,
      lstatImplementation: async (path) => {
        const facts = await lstat(path);
        if (facts.isFile()) facts.size = 0;
        return facts;
      },
    }),
    (error) => {
      assert.ok(slaWorkerCredentialFromPreparationError(error));
      assert.equal(error.credentialCleanupEvidence.status, "removed");
      return true;
    },
  );
});

test("directory creation errors do not disclose the input or invent a recovery handle", async () => {
  await assert.rejects(
    prepareSlaWorkerCredential(passwordUrl, {
      makeDirectoryImplementation: async () => {
        throw injectedFailure();
      },
      restrictPath,
    }),
    (error) => {
      assertRedacted(error);
      assert.equal(slaWorkerCredentialFromPreparationError(error), null);
      return true;
    },
  );
});

test("uninspectable credential directory fails cleanup without destructive calls", async () => {
  const credential = await prepareSlaWorkerCredential(passwordUrl, {
    restrictPath,
  });
  const calls = [];
  try {
    await assert.rejects(
      removeSlaWorkerCredential(credential, {
        lstatImplementation: async () => {
          throw injectedFailure();
        },
        unlinkImplementation: async () => {
          calls.push("unlink");
        },
        rmdirImplementation: async () => {
          calls.push("rmdir");
        },
      }),
      (error) => {
        assertRedacted(error);
        assert.equal(error.credentialCleanupEvidence.status, "failed");
        return true;
      },
    );
    assert.deepEqual(calls, []);
    assert.equal(await readFile(credential.file, "utf8"), `${passwordUrl}\n`);
  } finally {
    await removeSlaWorkerCredential(credential);
  }
});
