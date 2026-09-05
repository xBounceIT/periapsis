import { Buffer } from "node:buffer";
import { spawn, spawnSync } from "node:child_process";
import { realpathSync, statSync } from "node:fs";
import { win32 } from "node:path";
import process from "node:process";
import { clearTimeout, setTimeout } from "node:timers";

const activeProcessTrees = new Set();

function boundedInteger(value, label, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

export function windowsTaskkillPath(systemRoot = process.env.SystemRoot) {
  const normalizedRoot =
    typeof systemRoot === "string" ? win32.normalize(systemRoot) : "";
  const parsedRoot = win32.parse(normalizedRoot);
  if (
    normalizedRoot.length === 0 ||
    normalizedRoot.length > 260 ||
    !/^[A-Za-z]:\\$/.test(parsedRoot.root) ||
    win32.dirname(normalizedRoot).toLowerCase() !==
      parsedRoot.root.toLowerCase() ||
    win32.basename(normalizedRoot).toLowerCase() !== "windows"
  ) {
    throw new Error("Windows system root boundary is invalid");
  }
  return win32.join(normalizedRoot, "System32", "taskkill.exe");
}

export function preflightWindowsSystemTools({
  platformName = process.platform,
  realpathImplementation = realpathSync.native,
  statImplementation = statSync,
  systemRoot = process.env.SystemRoot,
} = {}) {
  if (platformName !== "win32") {
    return null;
  }
  if (
    typeof realpathImplementation !== "function" ||
    typeof statImplementation !== "function"
  ) {
    throw new TypeError("Windows system-tool verifier is invalid");
  }
  const taskkill = windowsTaskkillPath(systemRoot);
  const system32 = win32.dirname(taskkill);
  const tools = {
    icacls: win32.join(system32, "icacls.exe"),
    taskkill,
    whoami: win32.join(system32, "whoami.exe"),
  };
  for (const [name, path] of Object.entries(tools)) {
    let canonical;
    let facts;
    try {
      canonical = realpathImplementation(path);
      facts = statImplementation(path);
    } catch (error) {
      throw new Error(`Windows ${name} system tool is unavailable`, {
        cause: error,
      });
    }
    if (
      typeof canonical !== "string" ||
      win32.normalize(canonical).toLowerCase() !==
        win32.normalize(path).toLowerCase() ||
      typeof facts?.isFile !== "function" ||
      !facts.isFile()
    ) {
      throw new Error(`Windows ${name} system tool boundary is invalid`);
    }
  }
  return Object.freeze(tools);
}

export function terminateWindowsProcessTree(
  pid,
  {
    spawnSyncImplementation = spawnSync,
    systemRoot,
    taskkillPath = windowsTaskkillPath(systemRoot),
  } = {},
) {
  if (!Number.isSafeInteger(pid) || pid < 1) {
    throw new TypeError("Windows process-tree PID is invalid");
  }
  if (typeof spawnSyncImplementation !== "function") {
    throw new TypeError("Windows process-tree terminator is invalid");
  }
  const result = spawnSyncImplementation(
    taskkillPath,
    ["/PID", String(pid), "/T", "/F"],
    {
      encoding: "utf8",
      env: {
        SystemRoot: systemRoot ?? process.env.SystemRoot ?? "C:\\Windows",
      },
      timeout: 10_000,
      windowsHide: true,
    },
  );
  if (result.error || result.status !== 0 || result.signal) {
    return new Error("Windows process tree termination failed", {
      cause: result.error,
    });
  }
  return null;
}

function terminateProcessTree(entry) {
  if (!Number.isSafeInteger(entry.child.pid) || entry.child.pid < 1) {
    return new Error("tracked process tree has no valid PID");
  }
  if (process.platform === "win32") {
    return terminateWindowsProcessTree(entry.child.pid, {
      taskkillPath: entry.windowsTaskkillPath,
    });
  }
  try {
    process.kill(-entry.child.pid, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") {
      return error;
    }
  }
  return null;
}

function requestTreeTermination(entry, { retry = false } = {}) {
  if (entry.terminationRequested && !retry) {
    return;
  }
  entry.terminationRequested = true;
  entry.terminationAttempts += 1;
  entry.armCloseDeadline();
  try {
    const error = entry.terminationImplementation(entry);
    if (error) {
      entry.terminationError ??= error;
    }
  } catch (error) {
    entry.terminationError ??=
      error instanceof Error
        ? error
        : new Error("process tree termination failed");
  }
}

export function terminateActiveProcessTrees() {
  for (const entry of activeProcessTrees) {
    requestTreeTermination(entry);
  }
}

export function activeProcessTreeCount() {
  return activeProcessTrees.size;
}

export function activeProcessTreePids() {
  return Object.freeze(
    [...activeProcessTrees]
      .map((entry) => entry.child.pid)
      .filter(
        (pid) => Number.isSafeInteger(pid) && pid > 0 && pid <= 4_294_967_295,
      )
      .toSorted((a, b) => a - b),
  );
}

function detachUnquiescedProcessTree(entry) {
  entry.child.stdout?.destroy();
  entry.child.stderr?.destroy();
  entry.child.unref();
}

export async function terminateAndAwaitActiveProcessTrees({
  timeoutMs = 10_000,
} = {}) {
  boundedInteger(timeoutMs, "tracked process-tree quiescence timeout", 30_000);
  const entries = [...activeProcessTrees];
  if (entries.length === 0) {
    return Object.freeze({
      observed: 0,
      remaining: 0,
      terminationRequestFailures: 0,
    });
  }
  for (const entry of entries) {
    requestTreeTermination(entry, { retry: true });
  }
  let timeout;
  let timedOut = false;
  try {
    await Promise.race([
      Promise.all(entries.map((entry) => entry.closePromise)),
      new Promise((_, rejectPromise) => {
        timeout = setTimeout(() => {
          timedOut = true;
          rejectPromise(new Error("tracked process-tree quiescence timed out"));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    const remainingEntries = entries.filter((entry) =>
      activeProcessTrees.has(entry),
    );
    for (const entry of remainingEntries) {
      detachUnquiescedProcessTree(entry);
    }
    const terminationErrors = remainingEntries
      .map((entry) => entry.terminationError)
      .filter((entryError) => entryError instanceof Error);
    const quiescenceError = new AggregateError(
      [...terminationErrors, error],
      `tracked process-tree quiescence failed with ${remainingEntries.length} remaining`,
      { cause: error },
    );
    Object.defineProperty(quiescenceError, "quiescenceEvidence", {
      configurable: false,
      enumerable: false,
      value: Object.freeze({
        observed: entries.length,
        remaining: remainingEntries.length,
        timedOut,
        terminationRequestFailures: terminationErrors.length,
      }),
      writable: false,
    });
    throw quiescenceError;
  } finally {
    clearTimeout(timeout);
  }
  if (entries.some((entry) => activeProcessTrees.has(entry))) {
    throw new Error("tracked process-tree close accounting drifted");
  }
  return Object.freeze({
    observed: entries.length,
    remaining: 0,
    terminationRequestFailures: entries.filter(
      (entry) => entry.terminationError instanceof Error,
    ).length,
  });
}

export function runTrackedCommand(
  command,
  args,
  {
    cwd,
    env,
    closeGraceMs = 10_000,
    maxOutputBytes = 2 * 1024 * 1024,
    terminationImplementation = terminateProcessTree,
    timeoutMs = 60_000,
    windowsTaskkillPath: preflightedTaskkillPath,
  } = {},
) {
  if (
    typeof command !== "string" ||
    command.length === 0 ||
    command.length > 4096 ||
    !Array.isArray(args) ||
    !args.every((value) => typeof value === "string" && value.length <= 8192) ||
    typeof cwd !== "string" ||
    typeof env !== "object" ||
    env === null ||
    Array.isArray(env) ||
    typeof terminationImplementation !== "function"
  ) {
    throw new TypeError("tracked command boundary is malformed");
  }
  // Ingress may use the CLI's bounded 30-minute deadline plus shutdown grace.
  boundedInteger(timeoutMs, "tracked command timeout", 30 * 60_000 + 5_000);
  boundedInteger(closeGraceMs, "tracked command close grace", 30_000);
  boundedInteger(
    maxOutputBytes,
    "tracked command output bound",
    16 * 1024 * 1024,
  );
  if (
    process.platform === "win32" &&
    (typeof preflightedTaskkillPath !== "string" ||
      preflightedTaskkillPath.length === 0 ||
      win32.normalize(preflightedTaskkillPath).toLowerCase() !==
        windowsTaskkillPath(
          win32.dirname(win32.dirname(preflightedTaskkillPath)),
        ).toLowerCase())
  ) {
    throw new TypeError("preflighted Windows taskkill boundary is required");
  }

  return new Promise((resolvePromise) => {
    const child = spawn(command, args, {
      cwd,
      detached: true,
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let closeDeadline;
    let closePromiseResolver;
    let commandSettled = false;
    let timeout;
    const closePromise = new Promise((resolveClose) => {
      closePromiseResolver = resolveClose;
    });
    const settleCommand = (result) => {
      if (!commandSettled) {
        commandSettled = true;
        resolvePromise(result);
      }
    };
    const entry = {
      armCloseDeadline: () => {
        if (closeDeadline !== undefined) {
          return;
        }
        closeDeadline = setTimeout(() => {
          entry.closeDeadlineExpired = true;
          clearTimeout(timeout);
          const deadlineError = new Error(
            "tracked process tree did not quiesce before its close deadline",
          );
          const resultError =
            entry.terminationError instanceof Error
              ? new AggregateError(
                  [entry.terminationError, deadlineError],
                  "tracked command termination failed to quiesce",
                  { cause: entry.terminationError },
                )
              : deadlineError;
          settleCommand({
            closeDeadlineExpired: true,
            error: resultError,
            outputExceeded: entry.outputExceeded,
            signal: null,
            status: null,
            stderr,
            stdout,
            terminated: entry.terminationRequested,
            timedOut: entry.timedOut,
            treeQuiesced: false,
          });
        }, closeGraceMs);
      },
      child,
      closeDeadlineExpired: false,
      closePromise,
      outputExceeded: false,
      terminationAttempts: 0,
      terminationImplementation,
      terminationError: null,
      terminationRequested: false,
      timedOut: false,
      windowsTaskkillPath: preflightedTaskkillPath,
    };
    activeProcessTrees.add(entry);
    let error;
    let stderr = "";
    let stdout = "";
    const append = (current, chunk) => {
      const next = current + chunk.toString("utf8");
      if (Buffer.byteLength(next) > maxOutputBytes) {
        entry.outputExceeded = true;
        requestTreeTermination(entry);
        return current;
      }
      return next;
    };
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.once("error", (spawnError) => {
      error = spawnError;
      requestTreeTermination(entry);
    });
    timeout = setTimeout(() => {
      entry.timedOut = true;
      requestTreeTermination(entry);
    }, timeoutMs);
    child.once("close", (status, signal) => {
      clearTimeout(timeout);
      clearTimeout(closeDeadline);
      activeProcessTrees.delete(entry);
      closePromiseResolver();
      settleCommand({
        closeDeadlineExpired: entry.closeDeadlineExpired,
        error: error ?? entry.terminationError,
        outputExceeded: entry.outputExceeded,
        signal,
        status,
        stderr,
        stdout,
        terminated: entry.terminationRequested,
        timedOut: entry.timedOut,
        treeQuiesced: true,
      });
    });
  });
}
