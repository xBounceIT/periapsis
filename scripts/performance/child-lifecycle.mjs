import { clearTimeout, setTimeout } from "node:timers";

function assertChildBoundary(child, activeChildren) {
  if (
    typeof child !== "object" ||
    child === null ||
    typeof child.once !== "function" ||
    typeof child.off !== "function" ||
    typeof child.kill !== "function" ||
    !(activeChildren instanceof Set)
  ) {
    throw new TypeError("active child boundary is malformed");
  }
}

export function trackChildUntilClose(child, activeChildren) {
  assertChildBoundary(child, activeChildren);
  if (activeChildren.has(child) || activeChildren.size >= 64) {
    throw new TypeError("active child is already tracked");
  }
  activeChildren.add(child);
  return new Promise((resolvePromise) => {
    let childError = null;
    const handleError = (error) => {
      childError ??=
        error instanceof Error ? error : new Error("child process failed");
    };
    child.on("error", handleError);
    child.once("close", (status, signal) => {
      child.off("error", handleError);
      activeChildren.delete(child);
      resolvePromise(
        Object.freeze({ error: childError, signal: signal ?? null, status }),
      );
    });
  });
}

export async function terminateAndAwaitActiveChildren(
  activeChildren,
  { timeoutMs = 10_000 } = {},
) {
  if (
    !(activeChildren instanceof Set) ||
    activeChildren.size > 64 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000
  ) {
    throw new TypeError("active child quiescence boundary is malformed");
  }
  const children = [...activeChildren];
  if (children.length === 0) {
    return Object.freeze({
      observed: 0,
      remaining: 0,
      terminationRequestFailures: 0,
    });
  }
  const terminationErrors = [];
  const closePromises = children.map((child) => {
    assertChildBoundary(child, activeChildren);
    return new Promise((resolvePromise) => child.once("close", resolvePromise));
  });
  for (const child of children) {
    try {
      child.kill();
    } catch (error) {
      terminationErrors.push(
        error instanceof Error
          ? error
          : new Error("child termination request failed"),
      );
    }
  }
  let timeout;
  try {
    await Promise.race([
      Promise.all(closePromises),
      new Promise((_, rejectPromise) => {
        timeout = setTimeout(
          () => rejectPromise(new Error("active child quiescence timed out")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
  if (activeChildren.size !== 0) {
    throw new AggregateError(
      terminationErrors,
      `active child quiescence failed with ${activeChildren.size} remaining`,
    );
  }
  return Object.freeze({
    observed: children.length,
    remaining: 0,
    terminationRequestFailures: terminationErrors.length,
  });
}
