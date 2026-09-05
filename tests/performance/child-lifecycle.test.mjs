import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { setImmediate } from "node:timers";
import test from "node:test";

import {
  terminateAndAwaitActiveChildren,
  trackChildUntilClose,
} from "../../scripts/performance/child-lifecycle.mjs";

class FakeChild extends EventEmitter {
  constructor(onKill = () => undefined) {
    super();
    this.onKill = onKill;
  }

  kill() {
    return this.onKill(this);
  }
}

test("child error never settles or untracks before close", async () => {
  const active = new Set();
  const child = new FakeChild();
  const closed = trackChildUntilClose(child, active);
  let settled = false;
  void closed.then(() => {
    settled = true;
  });

  child.emit("error", new Error("injected kill failure"));
  await Promise.resolve();
  assert.equal(settled, false);
  assert.equal(active.has(child), true);

  child.emit("close", 1, null);
  const outcome = await closed;
  assert.equal(outcome.status, 1);
  assert.match(outcome.error.message, /injected kill failure/);
  assert.equal(active.size, 0);
});

test("quiescence terminates and awaits every tracked child", async () => {
  const active = new Set();
  const children = Array.from(
    { length: 3 },
    () =>
      new FakeChild((child) => {
        setImmediate(() => child.emit("close", null, "SIGTERM"));
        return true;
      }),
  );
  const lifecycles = children.map((child) =>
    trackChildUntilClose(child, active),
  );
  const evidence = await terminateAndAwaitActiveChildren(active, {
    timeoutMs: 1_000,
  });
  await Promise.all(lifecycles);
  assert.deepEqual(evidence, {
    observed: 3,
    remaining: 0,
    terminationRequestFailures: 0,
  });
  assert.equal(active.size, 0);
});

test("quiescence fails closed while a child remains active", async () => {
  const active = new Set();
  const child = new FakeChild(() => false);
  const lifecycle = trackChildUntilClose(child, active);
  await assert.rejects(
    terminateAndAwaitActiveChildren(active, { timeoutMs: 10 }),
    /quiescence timed out/,
  );
  assert.equal(active.has(child), true);
  child.emit("close", null, "SIGTERM");
  await lifecycle;
  assert.equal(active.size, 0);
});
