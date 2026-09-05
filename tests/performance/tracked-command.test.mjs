import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rmdir, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import test from "node:test";
import { setTimeout } from "node:timers";

import {
  activeProcessTreeCount,
  activeProcessTreePids,
  preflightWindowsSystemTools,
  runTrackedCommand,
  terminateAndAwaitActiveProcessTrees,
  terminateActiveProcessTrees,
  terminateWindowsProcessTree,
  windowsTaskkillPath,
} from "../../scripts/performance/tracked-command.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const windowsSystemTools = preflightWindowsSystemTools();

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") {
      return false;
    }
    throw error;
  }
}

function forceKill(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) {
    return;
  }
  if (process.platform === "win32") {
    const result = spawnSync(
      windowsTaskkillPath(),
      ["/PID", String(pid), "/T", "/F"],
      {
        env: {
          SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
        },
        stdio: "ignore",
        timeout: 10_000,
        windowsHide: true,
      },
    );
    if (result.error || (result.status !== 0 && processIsAlive(pid))) {
      throw new Error(
        "test cleanup could not terminate the Windows process tree",
        {
          cause: result.error,
        },
      );
    }
    return;
  }
  try {
    process.kill(pid, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") {
      throw error;
    }
  }
}

async function waitUntilDead(pid) {
  const deadline = Date.now() + 2_000;
  while (processIsAlive(pid) && Date.now() < deadline) {
    // The process table is an evolving external state and must be observed in
    // order; parallel sleeps cannot prove that it became quiescent.
    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
  }
  return !processIsAlive(pid);
}

async function unlinkIfPresent(path) {
  try {
    await unlink(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

test("timeout kills a tracked wrapper and its grandchild", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-performance-process-tree-"),
  );
  const receiptPath = join(directory, "pids.json");
  let pids = [];
  const wrapper = `
    const { spawn } = require("node:child_process");
    const { writeFileSync } = require("node:fs");
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      stdio: "ignore"
    });
    writeFileSync(process.argv[1], JSON.stringify([process.pid, child.pid]));
    setInterval(() => {}, 1000);
  `;
  try {
    const result = await runTrackedCommand(
      process.execPath,
      ["-e", wrapper, receiptPath],
      {
        cwd: repositoryRoot,
        env: {
          PATH: process.env.PATH ?? "",
          SystemRoot: process.env.SystemRoot ?? "",
          TEMP: process.env.TEMP ?? tmpdir(),
          TMP: process.env.TMP ?? tmpdir(),
        },
        maxOutputBytes: 1024,
        timeoutMs: 750,
        windowsTaskkillPath: windowsSystemTools?.taskkill,
      },
    );
    assert.equal(result.timedOut, true);
    assert.equal(result.terminated, true);
    assert.equal(activeProcessTreeCount(), 0);
    pids = JSON.parse(await readFile(receiptPath, "utf8"));
    assert.equal(pids.length, 2);
    assert.equal(await waitUntilDead(pids[0]), true);
    assert.equal(await waitUntilDead(pids[1]), true);
  } finally {
    terminateActiveProcessTrees();
    for (const pid of pids) {
      forceKill(pid);
    }
    await unlinkIfPresent(receiptPath);
    await rmdir(directory);
  }
});

test("Windows tree termination uses the absolute system tool and reports failure", () => {
  assert.equal(
    windowsTaskkillPath("C:\\Windows"),
    "C:\\Windows\\System32\\taskkill.exe",
  );
  assert.throws(
    () => windowsTaskkillPath("C:\\untrusted"),
    /system root boundary is invalid/,
  );
  assert.throws(
    () => windowsTaskkillPath("C:\\fake\\Windows"),
    /system root boundary is invalid/,
  );
  assert.throws(
    () => windowsTaskkillPath("\\\\server\\share\\Windows"),
    /system root boundary is invalid/,
  );
  let observed;
  const failure = terminateWindowsProcessTree(4242, {
    systemRoot: "C:\\Windows",
    spawnSyncImplementation: (command, args, options) => {
      observed = { args, command, options };
      return { error: undefined, signal: null, status: 5 };
    },
  });
  assert.match(failure.message, /termination failed/);
  assert.equal(observed.command, "C:\\Windows\\System32\\taskkill.exe");
  assert.deepEqual(observed.args, ["/PID", "4242", "/T", "/F"]);
  assert.equal(observed.options.timeout, 10_000);
  assert.deepEqual(Object.keys(observed.options.env), ["SystemRoot"]);
});

test("Windows system tools require canonical local System32 files", () => {
  const observed = [];
  const tools = preflightWindowsSystemTools({
    platformName: "win32",
    realpathImplementation: (path) => {
      observed.push(path);
      return path;
    },
    statImplementation: () => ({ isFile: () => true }),
    systemRoot: "C:\\Windows",
  });
  assert.deepEqual(tools, {
    icacls: "C:\\Windows\\System32\\icacls.exe",
    taskkill: "C:\\Windows\\System32\\taskkill.exe",
    whoami: "C:\\Windows\\System32\\whoami.exe",
  });
  assert.deepEqual(observed, [tools.icacls, tools.taskkill, tools.whoami]);
  assert.throws(
    () =>
      preflightWindowsSystemTools({
        platformName: "win32",
        realpathImplementation: () => "C:\\redirected\\taskkill.exe",
        statImplementation: () => ({ isFile: () => true }),
        systemRoot: "C:\\Windows",
      }),
    /system tool boundary is invalid/,
  );
});

test("termination callback exceptions become bounded command failures", async () => {
  const result = await runTrackedCommand(
    process.execPath,
    ["-e", "setTimeout(() => {}, 150)"],
    {
      cwd: repositoryRoot,
      env: {
        PATH: process.env.PATH ?? "",
        SystemRoot: process.env.SystemRoot ?? "",
      },
      maxOutputBytes: 1024,
      terminationImplementation: () => {
        throw new Error("injected terminator failure");
      },
      timeoutMs: 25,
      windowsTaskkillPath: windowsSystemTools?.taskkill,
    },
  );
  assert.equal(result.timedOut, true);
  assert.equal(result.terminated, true);
  assert.equal(result.treeQuiesced, true);
  assert.match(result.error.message, /injected terminator failure/);
  assert.equal(activeProcessTreeCount(), 0);
});

test("failed termination hands an unclosed tree to bounded central quiescence", async () => {
  let pid;
  try {
    const result = await runTrackedCommand(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      {
        closeGraceMs: 25,
        cwd: repositoryRoot,
        env: {
          PATH: process.env.PATH ?? "",
          SystemRoot: process.env.SystemRoot ?? "",
        },
        maxOutputBytes: 1024,
        terminationImplementation: () => {
          throw new Error("injected persistent terminator failure");
        },
        timeoutMs: 25,
        windowsTaskkillPath: windowsSystemTools?.taskkill,
      },
    );
    assert.equal(result.timedOut, true);
    assert.equal(result.closeDeadlineExpired, true);
    assert.equal(result.treeQuiesced, false);
    assert.match(result.error.message, /failed to quiesce/);
    assert.equal(activeProcessTreeCount(), 1);
    [pid] = activeProcessTreePids();
    assert.ok(Number.isSafeInteger(pid));
    await assert.rejects(
      terminateAndAwaitActiveProcessTrees({ timeoutMs: 25 }),
      /quiescence failed with 1 remaining/,
    );
    assert.deepEqual(activeProcessTreePids(), [pid]);
  } finally {
    if (pid !== undefined) {
      forceKill(pid);
      assert.equal(await waitUntilDead(pid), true);
      const deadline = Date.now() + 2_000;
      while (activeProcessTreeCount() !== 0 && Date.now() < deadline) {
        // A close event follows OS process-table quiescence asynchronously.
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 25));
      }
    }
    assert.equal(activeProcessTreeCount(), 0);
  }
});
