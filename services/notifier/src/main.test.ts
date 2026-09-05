import { createServer } from "node:http";

import { describe, expect, it, vi } from "vitest";

import { superviseNotifier } from "./main.js";

describe("notifier process supervision", () => {
  it("propagates shutdown, drains the runtime, and closes the listener", async () => {
    const stop = new AbortController();
    const server = createServer((_request, response) => response.end());
    const listening = new Promise<void>((resolve) => {
      server.once("listening", resolve);
    });
    const run = vi.fn(
      async (signal: AbortSignal) =>
        new Promise<void>((resolve) => {
          if (signal.aborted) resolve();
          else
            signal.addEventListener("abort", () => resolve(), { once: true });
        }),
    );
    const supervised = superviseNotifier({
      server,
      runtime: { run },
      signal: stop.signal,
      host: "127.0.0.1",
      port: 0,
    });

    await listening;
    stop.abort(new DOMException("test shutdown", "AbortError"));

    await expect(supervised).resolves.toBeUndefined();
    expect(run).toHaveBeenCalledOnce();
    expect(run.mock.calls[0]?.[0].aborted).toBe(true);
    expect(server.listening).toBe(false);
  });

  it("fails closed when the worker loop stops without a shutdown request", async () => {
    const server = createServer((_request, response) => response.end());

    await expect(
      superviseNotifier({
        server,
        runtime: { async run() {} },
        signal: new AbortController().signal,
        host: "127.0.0.1",
        port: 0,
      }),
    ).rejects.toThrow("notification runtime stopped unexpectedly");
    expect(server.listening).toBe(false);
  });
});
