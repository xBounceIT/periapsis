// @vitest-environment node

import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

it("starts the real web entrypoint after initializing proxy trust", async () => {
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const address = reservation.address();
  if (address === null || typeof address === "string") {
    throw new Error("test listener did not allocate a TCP port");
  }
  await new Promise<void>((resolve, reject) => {
    reservation.close((error) => (error ? reject(error) : resolve()));
  });

  // Node 24 executes the source entrypoint with native type stripping. Importing
  // the module in Vitest would skip its CLI branch and miss initialization bugs.
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("./index.ts", import.meta.url))],
    {
      env: {
        ...process.env,
        PERIAPSIS_ENV: "test",
        PERIAPSIS_API_URL: "http://127.0.0.1:8080",
        PERIAPSIS_WEB_ADDR: `127.0.0.1:${address.port}`,
        PERIAPSIS_WEB_PROXY_ONLY: "false",
        PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS: "172.30.240.4/32",
      },
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  const closed = once(child, "close");
  let startupTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      startupTimer = setTimeout(
        () => reject(new Error("web entrypoint did not start")),
        5_000,
      );
      child.once("error", reject);
      child.once("exit", (code) => {
        reject(new Error(`web entrypoint exited before startup: ${code}`));
      });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => {
        output += chunk.toString();
        if (output.includes('"event":"web_started"')) resolve();
      });
    });
    const response = await fetch(
      `http://127.0.0.1:${address.port}/health/live`,
      { signal: AbortSignal.timeout(2_000) },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: "alive",
      service: "web",
    });
  } finally {
    clearTimeout(startupTimer);
    child.kill();
    await closed;
  }
});
